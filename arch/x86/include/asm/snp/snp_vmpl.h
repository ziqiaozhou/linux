#ifndef SNP_UTILS_H
#define SNP_UTILS_H

#define RMP_READ (1 << 8)
#define RMP_WRITE (1 << 9)
#define RMP_USER_EXE (1 << 10)
#define RMP_KERN_EXE (1 << 11)
#define RMP_VMSA (1 << 16)
#define RMP_NO_WRITE (RMP_READ | RMP_USER_EXE | RMP_KERN_EXE)
#define RMP_RWX (RMP_NO_WRITE | RMP_WRITE)
#define RMP_PROT_MASK (RMP_RWX | RMP_VMSA)

#define SEV_GHCB_USAGE_VTL_RETURN 2
#define HV_X64_REGISTER_SEV_CONTROL 0x00090040 // register vmsa

#define SNP_VMPL0_DEV_ADDR 0xfef50000
#define SNP_VMPL0_DEV_MAGIC 0xfeeddead
#define SNP_VMPL_SET_OP 0xffffffff
#define SNP_VMPL_WAKE_AP_OP 0xfffffffe
#define SNP_PAGE_BITS 12
#define MAX_PAGES_PER_SNP_REQ ((1 << SNP_PAGE_BITS) - 1)

union snp_vmpl_request {
	struct {
		u64 values[3];
	};
	struct {
		u64 npages : 12;
		u64 gpn : 52;
		u64 op : 32;
		u64 cpu : 32;
	};
};

extern bool snp_direct_linux2;

void hv_sev_halt(int val);

#ifdef _BOOT_COMPRESSED
int ghcb_printf(const char *fmt, ...);
#else
#define ghcb_printf printk
#endif

int snp_write_reg(u32 reg, u64 val, u8 vtl);
void snp_vtl_enter(unsigned vtl);
void _snp_protect_memory(u64 start_vaddr, u64 end_vaddr, u64 rmp_prot,
			 unsigned vmpl);
unsigned snp_get_vmpl(void);
bool snp_is_vmpl0(void);
void vmpl_channel_process(union snp_vmpl_request *req);

int snp_vmpl0_set_memory_shared_private(unsigned long paddr,
					unsigned int npages, int op);

extern int (*snp_wake_up_cpu)(int cpu);

#endif
