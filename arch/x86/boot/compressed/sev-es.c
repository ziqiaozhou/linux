// SPDX-License-Identifier: GPL-2.0
/*
 * AMD Encrypted Register State Support
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

/*
 * misc.h needs to be first because it knows how to include the other kernel
 * headers in the pre-decompression code in a way that does not break
 * compilation.
 */
#include "misc.h"

#include <asm/pgtable_types.h>
#include <asm/sev-es.h>
#include <asm/trapnr.h>
#include <asm/trap_pf.h>
#include <asm/msr-index.h>
#include <asm/fpu/xcr.h>
#include <asm/ptrace.h>
#include <asm/svm.h>
#include <asm/sev-snp.h>

#include "error.h"

struct ghcb boot_ghcb_page __aligned(PAGE_SIZE);
struct ghcb *boot_ghcb;

/*
 * Copy a version of this function here - insn-eval.c can't be used in
 * pre-decompression code.
 */
static bool insn_has_rep_prefix(struct insn *insn)
{
	insn_byte_t p;
	int i;

	insn_get_prefixes(insn);

	for_each_insn_prefix(insn, i, p) {
		if (p == 0xf2 || p == 0xf3)
			return true;
	}

	return false;
}

/*
 * Only a dummy for insn_get_seg_base() - Early boot-code is 64bit only and
 * doesn't use segments.
 */
static unsigned long insn_get_seg_base(struct pt_regs *regs, int seg_reg_idx)
{
	return 0UL;
}

/* Provides sev_es_{wr,rd}_ghcb_msr() */
#include "sev-common.c"

static enum es_result vc_decode_insn(struct es_em_ctxt *ctxt)
{
	char buffer[MAX_INSN_SIZE];
	enum es_result ret;

	memcpy(buffer, (unsigned char *)ctxt->regs->ip, MAX_INSN_SIZE);

	insn_init(&ctxt->insn, buffer, MAX_INSN_SIZE, 1);
	insn_get_length(&ctxt->insn);

	ret = ctxt->insn.immediate.got ? ES_OK : ES_DECODE_FAILED;

	return ret;
}

static enum es_result vc_write_mem(struct es_em_ctxt *ctxt,
				   void *dst, char *buf, size_t size)
{
	memcpy(dst, buf, size);

	return ES_OK;
}

static enum es_result vc_read_mem(struct es_em_ctxt *ctxt,
				  void *src, char *buf, size_t size)
{
	memcpy(buf, src, size);

	return ES_OK;
}

#undef __init
#undef __pa
#define __init
#define __pa(x)	((unsigned long)(x))

#define __BOOT_COMPRESSED

/* Basic instruction decoding support needed */
#include "../../lib/inat.c"
#include "../../lib/insn.c"

/* Include code for early handlers */
#include "../../kernel/sev-es-shared.c"

static bool early_setup_sev_es(void)
{
	if (!sev_es_negotiate_protocol())
		sev_es_terminate(GHCB_SEV_ES_REASON_PROTOCOL_UNSUPPORTED);

	if (set_page_decrypted((unsigned long)&boot_ghcb_page))
		return false;

	/* Page is now mapped decrypted, clear it */
	memset(&boot_ghcb_page, 0, sizeof(boot_ghcb_page));

	boot_ghcb = &boot_ghcb_page;

	/* Initialize lookup tables for the instruction decoder */
	inat_init_tables();

	/* SEV-SNP guest requires the GHCB GPA must be registered */
	sev_snp_register_ghcb(__pa(&boot_ghcb_page));

	return true;
}

#include <asm/svm.h>
#include <asm/hyperv-tlfs.h>
#include <linux/version.h>
static bool vmpl_register_osid = false;

extern unsigned long verismo_register_early_ghcb_addr(void);
extern int ghcb_printf(const char *fmt, ...);
extern enum es_result sev_es_ghcb_hv_call(struct ghcb *ghcb,
				   struct es_em_ctxt *ctxt,
				   u64 exit_code, u64 exit_info_1,
				   u64 exit_info_2);
int only_set_pte_decrypted(unsigned long address);

struct ghcb * verismo_register_early_ghcb(struct boot_params *bp) {
	struct ghcb * ghcb;
	unsigned long ghcb_vaddr;

	extern bool sev_es_negotiate_protocol(void);
	if (!sev_es_negotiate_protocol()) {
		sev_es_terminate(GHCB_SEV_ES_REASON_PROTOCOL_UNSUPPORTED);
	}

	extern void init_snp(struct boot_params *bp);
	init_snp(bp);

	ghcb_vaddr = verismo_get_early_ghcb_addr();

	ghcb_printf("verismo_get_early_ghcb_addr() = %lx %lx\n",
		    verismo_get_early_ghcb_addr(), ghcb_vaddr);

	//early_set_memory_decrypted(ghcb_vaddr, PAGE_SIZE);
	if (only_set_pte_decrypted((unsigned long)ghcb_vaddr)){
		sev_es_terminate(0);
	}
	memset(ghcb_vaddr, 0, PAGE_SIZE);
	ghcb = (struct ghcb*) ghcb_vaddr;

	if (((u64)ghcb) % 0x1000 != 0) {
		sev_es_terminate(GHCB_SEV_ES_REASON_PROTOCOL_UNSUPPORTED);
	}

	sev_snp_register_ghcb((unsigned long)ghcb);

	ghcb_printf("__pa(ghcb) = %lx %lx\n", __pa(ghcb), sev_es_rd_ghcb_msr());
	if (sev_es_rd_ghcb_msr() != __pa(ghcb))
	{
		sev_es_terminate(0);
	}
	return ghcb;
}

void early_register_osid(struct boot_params * bp) {
	unsigned long ghcb_page;
	struct ghcb * ghcb;
	struct es_em_ctxt ctxt;

	u64 guest_id = 0x123;

	// No need to do early register;
	if (vmpl_register_osid) {
		return;
	}

	vmpl_register_osid = true;

	// register the early ghcb;
	ghcb = verismo_register_early_ghcb(bp);
	vc_ghcb_invalidate(ghcb);
	// register OS ID.
	ghcb_set_rcx(ghcb, HV_X64_MSR_GUEST_OS_ID);
	ghcb_set_rax(ghcb, guest_id);
	ghcb_set_rdx(ghcb, 0);
	sev_es_ghcb_hv_call(ghcb, &ctxt, SVM_EXIT_MSR, 1, 0);
}

void sev_es_shutdown_ghcb(void)
{
	if (!boot_ghcb)
		return;

	if (!sev_es_check_cpu_features())
		error("SEV-ES CPU Features missing.");

	/*
	 * GHCB Page must be flushed from the cache and mapped encrypted again.
	 * Otherwise the running kernel will see strange cache effects when
	 * trying to use that page.
	 */
	if (set_page_encrypted((unsigned long)&boot_ghcb_page))
		error("Can't map GHCB page encrypted");

	/*
	 * GHCB page is mapped encrypted again and flushed from the cache.
	 * Mark it non-present now to catch bugs when #VC exceptions trigger
	 * after this point.
	 */
	if (set_page_non_present((unsigned long)&boot_ghcb_page))
		error("Can't unmap GHCB page");
}

bool sev_es_check_ghcb_fault(unsigned long address)
{
	/* Check whether the fault was on the GHCB page */
	return ((address & PAGE_MASK) == (unsigned long)&boot_ghcb_page);
}

void do_boot_stage2_vc(struct pt_regs *regs, unsigned long exit_code)
{
	struct es_em_ctxt ctxt;
	enum es_result result;

	if (!boot_ghcb && !early_setup_sev_es())
		sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);

	vc_ghcb_invalidate(boot_ghcb);
	result = vc_init_em_ctxt(&ctxt, regs, exit_code);
	if (result != ES_OK)
		goto finish;

	switch (exit_code) {
	case SVM_EXIT_RDTSC:
	case SVM_EXIT_RDTSCP:
		result = vc_handle_rdtsc(boot_ghcb, &ctxt, exit_code);
		break;
	case SVM_EXIT_IOIO:
		result = vc_handle_ioio(boot_ghcb, &ctxt);
		break;
	case SVM_EXIT_CPUID:
		result = vc_handle_cpuid(boot_ghcb, &ctxt);
		break;
	default:
		result = ES_UNSUPPORTED;
		break;
	}

finish:
	if (result == ES_OK)
		vc_finish_insn(&ctxt);
	else if (result != ES_RETRY)
		sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);
}
