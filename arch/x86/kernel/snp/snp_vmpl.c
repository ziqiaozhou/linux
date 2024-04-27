#include "linux/acpi.h"
#include <linux/context_tracking.h>
#include <linux/kernel.h>
#include <linux/trace_events.h>

#include <asm/mshyperv.h>
#include <asm/page_types.h>
#include <asm/sev-es.h>
#include <asm/sev-snp.h>
#include <asm/svm.h>
#include <asm/virtext.h>

#include <asm/snp/snp_vmpl.h>

DEFINE_PER_CPU(struct vmcb_save_area *, current_vmsa);
static DEFINE_PER_CPU(union snp_vmpl_request *, vmpl_channel);

bool snp_direct_linux2 = false;
static bool disable_reflect_vc = false;

static int __init set_snp_direct_linux2(char *str)
{
	snp_direct_linux2 = true;
	disable_reflect_vc = true;
	return 0;
}
early_param("snp_direct_linux2", set_snp_direct_linux2);

static int __init early_refelct_vc(char *p)
{
	disable_reflect_vc = true;
	return 0;
}
early_param("disable_reflect_vc", early_refelct_vc);

void init_sev_feature(struct vmcb_save_area *vmsa)
{
	vmsa->sev_features = 0;
	vmsa->sev_feature_snp = 1;
	//vmsa->sev_feature_secure_tsc = 1;
	//vmsa->tsc_scale = 1;
	//vmsa->tsc_offset = 0;
	vmsa->sev_feature_vtom = disable_reflect_vc ? 0 : 1;
	vmsa->virtual_tom = disable_reflect_vc ? 0 : 0x8000000000;
	vmsa->sev_feature_alternate_injection = disable_reflect_vc ? 0 : 1;
	vmsa->sev_feature_reflectvc = disable_reflect_vc ? 0 : 1;
	vmsa->sev_feature_restrict_injection = disable_reflect_vc ? 1 : 0;
}

/* Provides sev_es_terminate() */
static inline void sev_es_wr_ghcb_msr(u64 val)
{
	u32 low, high;

	low = (u32)(val);
	high = (u32)(val >> 32);

	native_wrmsr(MSR_AMD64_SEV_ES_GHCB, low, high);
}

static inline u64 sev_es_rd_ghcb_msr(void)
{
	return __rdmsr(MSR_AMD64_SEV_ES_GHCB);
}

#include "../kernel/sev-common-shared.c"
#include "snp-vmpl-shared.c"

void hv_sev_halt(int val)
{
	sev_es_terminate(val);
}

/* HVCALL_SET_VP_REGISTERS
 *  vtl[0:4]: vtl value
 *  vtl[5]: use vtl
 */
int snp_write_reg(u32 reg, u64 val, u8 vtl)
{
	u64 control = ((u64)1 << HV_HYPERCALL_REP_COMP_OFFSET) |
		      HVCALL_SET_VP_REGISTERS;
	struct hv_set_vp_registers_input *input = NULL;
	int ret;
	unsigned long flags;

	local_irq_save(flags);
	input = *(struct hv_set_vp_registers_input **)this_cpu_ptr(
		hyperv_pcpu_input_arg);
	if (!input) {
		pr_err("Hyper-V: cannot allocate a shared page!");
		goto done;
	}

	memset(input, 0, sizeof(*input) + sizeof(input->element[0]));
	input->header.partitionid = HV_PARTITION_ID_SELF;
	input->header.vpindex = HV_VP_INDEX_SELF;
	input->header.inputvtl = vtl;
	input->element[0].name = reg;
	input->element[0].valuelow = val;
retry:
	ret = hv_do_hypercall(control, input, NULL);
	if (ret == 0x78) {
		goto retry;
	}
	if (ret) {
		pr_err("Hyper-V: failed to set the reg %x ret %x\n", reg, ret);
	}
done:
	local_irq_restore(flags);
	return ret;
}

u64 snp_read_reg(u32 reg, u8 vtl)
{
	u64 control = ((u64)1 << HV_HYPERCALL_REP_COMP_OFFSET) | HVCALL_GET_VP_REGISTERS;
	struct hv_get_vp_registers_input *input = NULL;
	struct hv_get_vp_registers_output *output = NULL;
	int ret;
	u64 val;
	unsigned long flags;

	val = 0;
	local_irq_save(flags);
	input = *(struct hv_get_vp_registers_input **)this_cpu_ptr(hyperv_pcpu_input_arg);
	output = (struct hv_get_vp_registers_output *)input;
	if (!input || !output) {
		pr_err("Hyper-V: cannot allocate a shared page!\n");
		goto done;
	}

	memset(input, 0, sizeof(*input) + sizeof(input->element[0]));
	input->header.partitionid = HV_PARTITION_ID_SELF;
	input->header.vpindex = HV_VP_INDEX_SELF;
	input->header.inputvtl = vtl;
	input->element[0].name0 = reg;
	ret = hv_do_hypercall(control, input, output);

	if (ret == 0)
		val = output->as64.low;
	else
		pr_err("Hyper-V: failed to get the reg %x\n", reg);
	local_irq_restore(flags);

	pr_info("Hyper-V: to get the reg %x %llx\n", reg, val);

done:
	return val;
}

void _snp_protect_memory(u64 start_vaddr, u64 end_vaddr, u64 rmp_prot,
			 unsigned vmpl)
{
	u64 va;
	u64 ret;
	union sev_rmp_adjust rmp_adjust;
	BUG_ON(rmp_prot & (~RMP_PROT_MASK));
	if (end_vaddr <= start_vaddr)
		return;
	rmp_adjust.as_uint64 = 0;
	rmp_adjust.target_vmpl = vmpl;
	rmp_adjust.as_uint64 |= rmp_prot;
	for (va = start_vaddr; va < end_vaddr; va += PAGE_SIZE) {
		RMPADJUST(va, 0, rmp_adjust, ret);
		BUG_ON(ret != 0);
	}
}

void snp_vtl_enter(unsigned vtl)
{
	union hv_ghcb {
		struct {
			u64 ghcb_data[511];
			u16 reserved;
			u16 version;
			u32 format;
		};
		struct {
			u8 target_vtl;
		};
	} * ghcb;
	struct vmcb_save_area *vmsa = this_cpu_read(current_vmsa);
	struct ghcb_state state;
	unsigned long flags;

	instrumentation_begin();
	trace_hardirqs_on_prepare();
	lockdep_hardirqs_on_prepare(CALLER_ADDR0);
	instrumentation_end();
	guest_enter_irqoff();
	lockdep_hardirqs_on(CALLER_ADDR0);

	vmsa->guest_error_code = 0xfff;
	do {
		local_irq_save(flags);
		native_irq_enable();
		ghcb = (union hv_ghcb *)sev_es_get_ghcb(&state);
		ghcb->format = SEV_GHCB_USAGE_VTL_RETURN;
		ghcb->target_vtl = vtl;
		VMGEXIT();
		sev_es_put_ghcb(&state);
		local_irq_restore(flags);
	} while (vmsa->guest_error_code == 0xfff);

	lockdep_hardirqs_off(CALLER_ADDR0);
	guest_exit_irqoff();
	instrumentation_begin();
	trace_hardirqs_off_finish();
	instrumentation_end();
	smp_wmb();
}

