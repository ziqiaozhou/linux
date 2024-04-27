static u8 test_page[PAGE_SIZE] __aligned(PAGE_SIZE);

#ifdef __BOOT_COMPRESSED

void hv_sev_debugbreak(u32 val)
{
	u32 low, high;
	val = ((val & (u32)0xf) << 12) | (u32)0xf03;
	asm volatile ("rdmsr" : "=a" (low), "=d" (high) : "c" (0xc0010130));
	asm volatile ("wrmsr\n\r"
		      "rep; vmmcall\n\r"
		      :: "c" (0xc0010130), "a" (val), "d" (0x0));
	asm volatile ("wrmsr" :: "c" (0xc0010130), "a" (low), "d" (high));
}

static int hv_sev_printf(const char *fmt, va_list ap)
{
	char buf[64];
	int len;
	int idx;
	int left;
	unsigned long flags;
	u32 orig_low, orig_high;
	u32 low, high;
	len = vsprintf(buf, fmt, ap);
	asm volatile("rdmsr"
		     : "=a"(orig_low), "=d"(orig_high)
		     : "c"(0xc0010130));
	for (idx = 0; idx < len; idx += 6) {
		left = len - idx;
		if (left > 6)
			left = 6;
		low = 0xf03;
		high = 0;
		memcpy((char *)&low + 2, &buf[idx], left == 1 ? 1 : 2);
		if (left > 2)
			memcpy((char *)&high, &buf[idx + 2], left - 2);
		asm volatile("wrmsr\n\r"
			     "rep; vmmcall\n\r" ::"c"(0xc0010130),
			     "a"(low), "d"(high));
	}
	asm volatile("wrmsr" ::"c"(0xc0010130), "a"(orig_low), "d"(orig_high));
	return len;
}

int ghcb_printf(const char *fmt, ...)
{
	va_list args;
	int printed = 0;
	va_start(args, fmt);
	printed = hv_sev_printf(fmt, args);
	va_end(args);
	return printed;
}
#endif

typedef union _SEV_GHCB_MSR {
	u64 val;
	struct {
		u64 low : 32;
		u64 hight : 32;
	};
	struct {
		u64 ghcb_info : 12;
		u64 gpa : 40;
		u64 extra : 12;
	};
} sev_ghcb_msr;

#define HVCALL_VTL_CALL 0x0011
#define HPL_HYPERCALL_FLAGS_SWITCHES_VTL 0x4
#define HPL_HYPERCALL_FLAGS_SWITCHES_VTL 0x4
#define GHCB_INFO_SPECIAL_HYPERCALL 0xf00
#define GHCB_MSR 0xc0010130


static u64 _snp_send_vmpl_via_ghcb_msr(union snp_vmpl_request *req)
{
	u32 low, high;
	sev_ghcb_msr msr_val;
	
	msr_val.ghcb_info = GHCB_INFO_SPECIAL_HYPERCALL;
	msr_val.gpa = 0x0;
	msr_val.extra = HVCALL_VTL_CALL;
	asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(GHCB_MSR));
	asm volatile("wrmsr\n\r"::"c"(GHCB_MSR),"a"(msr_val.val), "d"(msr_val.val >> 32));
	asm volatile(
		"rep; vmmcall\n\r"
		::
		"a"(SNP_VMPL0_DEV_MAGIC),
		"b"(req->values[0]),
		"c"(req->values[1]),
		"d"(req->values[2])
	);
	asm volatile("wrmsr" ::"c"(GHCB_MSR), "a"(low), "d"(high));
	return 0;
}

static void snp_send_vmpl_via_ghcb_msr(union snp_vmpl_request *req)
{
	#ifndef __BOOT_COMPRESSED
	preempt_disable();
	if (irqs_disabled()) {
		_snp_send_vmpl_via_ghcb_msr(req);
	} else {
		local_irq_disable();
		_snp_send_vmpl_via_ghcb_msr(req);
		local_irq_enable();
	}
	preempt_enable();
	#else 
	_snp_send_vmpl_via_ghcb_msr(req);
	#endif
}

static int snp_max_vmpl(void)
{
	static int max_vmpl = -1;
	unsigned int eax = 0x8000001f, ebx = 0, ecx = 0, edx = 0;
	if (max_vmpl != -1) {
		return max_vmpl;
	}
#ifdef __BOOT_COMPRESSED
	max_vmpl = 3;
#else
	native_cpuid(&eax, &ebx, &ecx, &edx);
	max_vmpl = ((ebx >> 12) & 0xf) - 1;
#endif
	return max_vmpl;
}

static bool snp_is_vmpl(unsigned target_vmpl)
{
	u64 err;
	static unsigned minimum_vmpl_level = 0;
	union sev_rmp_adjust rmp_adjust;

	if (minimum_vmpl_level > target_vmpl) {
		return false;
	}
	if (target_vmpl > snp_max_vmpl()) {
		return false;
	}
	/*
	 * RMPADJUST modifies RMP permissions of a lesser-privileged 
	 * privilege level. Here, clear the VMPL1 permission mask of the
	 * GHCB page. If the guest is not running at VMPL0, this will fail.
	 * If the guest is running at lower, it will succeed. Even if that 
	 * operation modifies permission bits.
	 */

	rmp_adjust.as_uint64 = 0;
	rmp_adjust.target_vmpl = target_vmpl + 1;
	RMPADJUST((unsigned long)test_page, RMP_PG_SIZE_4K, rmp_adjust, err);
	if (!err) {
		minimum_vmpl_level = target_vmpl + 1;
	}
	return !err;
}

bool snp_is_vmpl0(void)
{
#ifdef CONFIG_SNP_DIRECT_NEXT_VMPL
	// Cannot Check VMPL level before dynamic pvalidate since we do not
	// guarantee to have a validated test_page.
	return true;
#else
	return snp_is_vmpl(0);
#endif
}

unsigned snp_get_vmpl(void)
{
	static int current_vmpl = -1;
	if (current_vmpl != -1) {
		return current_vmpl;
	}
	for (current_vmpl = 0; current_vmpl < snp_max_vmpl(); ++current_vmpl) {
		if (snp_is_vmpl(current_vmpl)) {
			return current_vmpl;
		}
	}
	return snp_max_vmpl();
}


static DEFINE_PER_CPU(union snp_vmpl_request *, vmpl_channel);
static bool vmpl_channel_inited = false;

static union snp_vmpl_request *get_vmpl_channel(void)
{
	return vmpl_channel_inited ? this_cpu_read(vmpl_channel) : NULL;
}

#ifndef __BOOT_COMPRESSED
static int snp_set_vmpl_channel(void)
{
	union snp_vmpl_request *vmpl_req;
	int cpu;
	if (vmpl_channel_inited) {
		return 0;
	}
	for_each_possible_cpu (cpu) {
		vmpl_req = (union snp_vmpl_request *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
		memset(vmpl_req, 0, sizeof(*vmpl_req));
		vmpl_req->op = SNP_VMPL_SET_OP;
		vmpl_req->gpn = (__pa(vmpl_req) >> PAGE_SHIFT);
		vmpl_req->cpu = cpu;
		// Note: the security monitor does not support the vmpl_channel communication
		//snp_send_vmpl_via_ghcb_msr(vmpl_req);
		per_cpu(vmpl_channel, cpu) = vmpl_req;
		ghcb_printf("vmpl2: set vmpl_channel gpn to %llx\n",
			    (u64)vmpl_req->gpn);
	}
	vmpl_channel_inited = true;
	return 0;
}

int snp_vmpl_wake_ap(unsigned cpu, unsigned long vmsa_paddr)
{
	union snp_vmpl_request *vmpl_req; 
	snp_set_vmpl_channel();
	vmpl_req = get_vmpl_channel();
	memset(vmpl_req, 0, sizeof(*vmpl_req));
	vmpl_req->op = SNP_VMPL_WAKE_AP_OP;
	vmpl_req->gpn = (vmsa_paddr >> PAGE_SHIFT);
	vmpl_req->cpu = cpu;
#define HVCALL_VTL_CALL 0x0011
	// Note: the security monitor does not take hypercall-based VTL switch
	snp_send_vmpl_via_ghcb_msr(vmpl_req);
	return 0;
}
#endif

int snp_vmpl0_set_memory_shared_private(unsigned long paddr,
					unsigned int npages, int op)
{
	union snp_vmpl_request snp_page_req;
	u32 npages_per_call;
	while (npages) {
		memset(&snp_page_req, 0, sizeof(snp_page_req));
		snp_page_req.gpn = (paddr >> PAGE_SHIFT);
		snp_page_req.op = op;
		npages_per_call = (npages > MAX_PAGES_PER_SNP_REQ) ?
						MAX_PAGES_PER_SNP_REQ :
						npages;
		snp_page_req.npages = npages_per_call;
		// Note: the security monitor does not support the vmpl_channel communication
		snp_send_vmpl_via_ghcb_msr(&snp_page_req);
		npages -= npages_per_call;
		snp_page_req.gpn += npages_per_call;
	}
	return 0;
}
