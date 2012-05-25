
#include "module.h"

struct kernsym sym_security_ops;
struct security_operations *ptr_security_ops;

// mmap

int (*orig_security_file_mmap) (struct file *, unsigned long,
		unsigned long, unsigned long,
		unsigned long, unsigned long);

int tpe_security_file_mmap(struct file *file, unsigned long reqprot,
		unsigned long prot, unsigned long flags,
		unsigned long addr, unsigned long addr_only) {
	int ret = 0;

	if (file && (prot & PROT_EXEC)) {
		ret = tpe_allow_file(file, "mmap");
		if (IN_ERR(ret))
			goto out;
	}

	ret = orig_security_file_mmap(file, reqprot, prot, flags, addr, addr_only);

	out:

	return ret;
}

// mprotect

int (*orig_security_file_mprotect) (struct vm_area_struct *, unsigned long,
	unsigned long);

int tpe_security_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
		unsigned long prot) {
	int ret = 0;

	if (vma->vm_file && (prot & PROT_EXEC)) {
		ret = tpe_allow_file(vma->vm_file, "mprotect");
		if (IN_ERR(ret))
			goto out;
	}

	ret = orig_security_file_mprotect(vma, reqprot, prot);

	out:

	return ret;
}

// execve

int (*orig_bprm_check_security) (struct linux_binprm *);

int tpe_security_bprm_check(struct linux_binprm *bprm) {
	int ret = 0;

	if (bprm->file) {
		ret = tpe_allow_file(bprm->file, "exec");
		if (IN_ERR(ret))
			goto out;
	}

	ret = orig_bprm_check_security(bprm);

	out:

	return ret;
}

struct kernsym sym_proc_sys_file_operations;
struct file_operations *ptr_proc_sys_file_operations;

static ssize_t (*orig_proc_sys_write) (struct file *, const char __user *, size_t, loff_t *);

static ssize_t tpe_proc_sys_write(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos) {
	char filename[MAX_FILE_LEN], *f;
	ssize_t ret;

	f = tpe_d_path(file, filename, MAX_FILE_LEN);

	if (tpe_lock && !strncmp("/proc/sys/tpe", f, 13))
		return -EPERM;

	ret = orig_proc_sys_write(file, buf, count, ppos);

	return ret;
}

// lsmod

struct kernsym sym_modules_op;
struct seq_operations *ptr_modules_op;

int (*orig_m_show) (struct seq_file *, void *);

int tpe_m_show(struct seq_file *m, void *p) {

	if (tpe_lsmod && !capable(CAP_SYS_MODULE))
		return -EPERM;

	return orig_m_show(m, p);
}

// kallsyms

struct kernsym sym_kallsyms_operations;
struct file_operations *ptr_kallsyms_operations;

int (*orig_kallsyms_open) (struct inode *, struct file *);

int tpe_kallsyms_open(struct inode *inode, struct file *file) {

	if (tpe_proc_kallsyms && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	return orig_kallsyms_open(inode, file);
}

// ps restrict

struct kernsym sym_pid_dentry_operations;
struct dentry_operations *ptr_pid_dentry_operations;

int (*orig_pid_revalidate) (struct dentry *, struct nameidata *);

int tpe_pid_revalidate(struct dentry *dentry, struct nameidata *nd) {
	int ret = 0;

	if (tpe_ps && !capable(CAP_SYS_ADMIN) &&
		dentry->d_inode && dentry->d_inode->i_uid != get_task_uid(current) &&
		dentry->d_parent->d_inode && dentry->d_parent->d_inode->i_uid != get_task_uid(current) &&
		(!tpe_ps_gid || (tpe_ps_gid && !in_group_p(tpe_ps_gid))))
		return -EPERM;

	ret = orig_pid_revalidate(dentry, nd);

	return ret;
}

void printfail(const char *name) {
	printk(PKPRE "warning: unable to implement protections for %s\n", name);
}

// functions to set/unset write at the page that represents the given address
// this previously was code that disabled the write-protect bit of cr0, but
// this is much cleaner

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)

#if (defined(CONFIG_XEN) || defined(CONFIG_X86_PAE))
#include <asm/cacheflush.h>
#endif

// copied from centos5 arch/x86_64/mm/pageattr.c

static inline pte_t *tpe_lookup_address(unsigned long address, unsigned int *level)
{
	pgd_t *pgd = pgd_offset_k(address);
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	if (pgd_none(*pgd))
		return NULL;
	pud = pud_offset(pgd, address);
	if (!pud_present(*pud))
		return NULL;
	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd))
		return NULL;
	if (pmd_large(*pmd))
		return (pte_t *)pmd;
	pte = pte_offset_kernel(pmd, address);
	if (pte && !pte_present(*pte))
		pte = NULL;
	return pte;
}

#else
#define tpe_lookup_address(address, level) lookup_address(address, level);
#endif

static inline bool page_is_ro(
#if (defined(CONFIG_XEN) || defined(CONFIG_X86_PAE)) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	struct page *pg) {

	if (pg->flags & VM_WRITE) return false;
	else return true;

#else
	pte_t *pte) {

#if !defined(CONFIG_X86_64) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	if (pte_val(*pte) & _PAGE_RW) return false;
	else return true;
#else  
	if (pte->pte & _PAGE_RW) return false;
	else return true;
#endif

#endif
}

static inline void set_addr_rw(unsigned long addr, bool *flag) {

#if (defined(CONFIG_XEN) || defined(CONFIG_X86_PAE)) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	struct page *pg;

	pgprot_t prot;
	pg = virt_to_page(addr);

	if (!page_is_ro(pg)) *flag = false;
	else {
		prot.pgprot = VM_READ | VM_WRITE;
		change_page_attr(pg, 1, prot);
	}
#else
	unsigned int level;
	pte_t *pte;

	*flag = true;

	pte = tpe_lookup_address(addr, &level);

#if !defined(CONFIG_X86_64) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	if (!page_is_ro(pte)) *flag = false;
	else pte_val(*pte) |= _PAGE_RW;
#else
	if (!page_is_ro(pte)) *flag = false;
	else pte->pte |= _PAGE_RW;
#endif
#endif

}

static inline void set_addr_ro(unsigned long addr, bool flag) {

#if (defined(CONFIG_XEN) || defined(CONFIG_X86_PAE)) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	struct page *pg;

	if (!flag)
		return;

	pgprot_t prot;
	pg = virt_to_page(addr);
	prot.pgprot = VM_READ;
	change_page_attr(pg, 1, prot);
#else
	unsigned int level;
	pte_t *pte;

	if (!flag)
		return;

	pte = tpe_lookup_address(addr, &level);

#if !defined(CONFIG_X86_64) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
	pte_val(*pte) = pte_val(*pte) &~_PAGE_RW;
#else
	pte->pte = pte->pte &~_PAGE_RW;
#endif
#endif

}

void hijack_syscalls(void) {

	int ret;
	bool pte_ro;

	// hijack portions of the security_ops symbol; it's a pointer to a struct security_operations

	ret = find_symbol_address(&sym_security_ops, "security_ops");

	if (IN_ERR(ret))
		printfail("security_ops");
	else {
		memcpy(&ptr_security_ops, sym_security_ops.addr, sizeof(void *));

		memcpy(&orig_security_file_mmap, &ptr_security_ops->file_mmap, sizeof(void *));
		memcpy(&orig_security_file_mprotect, &ptr_security_ops->file_mprotect, sizeof(void *));
		memcpy(&orig_bprm_check_security, &ptr_security_ops->bprm_check_security, sizeof(void *));

		ptr_security_ops->file_mmap = tpe_security_file_mmap;
		ptr_security_ops->file_mprotect = tpe_security_file_mprotect;
		ptr_security_ops->bprm_check_security = tpe_security_bprm_check;
	}

	// hijack part of the pid_dentry_operations symbol; it's a dentry_operation struct (not a pointer)

	ret = find_symbol_address(&sym_pid_dentry_operations, "pid_dentry_operations");

	if (IN_ERR(ret))
		printfail("pid_dentry_operations");
	else {
		ptr_pid_dentry_operations = sym_pid_dentry_operations.addr;

		orig_pid_revalidate = ptr_pid_dentry_operations->d_revalidate;

		set_addr_rw((unsigned long)ptr_pid_dentry_operations, &pte_ro);
		ptr_pid_dentry_operations->d_revalidate = tpe_pid_revalidate;
		set_addr_ro((unsigned long)ptr_pid_dentry_operations, pte_ro);
	}

	// hijack part of the proc_sys_file_operations symbol; it's a file_operations struct (not a pointer)

	ret = find_symbol_address(&sym_proc_sys_file_operations, "proc_sys_file_operations");

	if (IN_ERR(ret))
		printfail("proc_sys_file_operations");
	else {
		ptr_proc_sys_file_operations = sym_proc_sys_file_operations.addr;

		orig_proc_sys_write = ptr_proc_sys_file_operations->write;

		set_addr_rw((unsigned long)ptr_proc_sys_file_operations, &pte_ro);
		ptr_proc_sys_file_operations->write = tpe_proc_sys_write;
		set_addr_ro((unsigned long)ptr_proc_sys_file_operations, pte_ro);
	}

	// hijack part of the modules_op symbol; it's a seq_operations struct (not a pointer)

	ret = find_symbol_address(&sym_modules_op, "modules_op");

	if (IN_ERR(ret))
		printfail("modules_op");
	else {
		ptr_modules_op = sym_modules_op.addr;

		orig_m_show = ptr_modules_op->show;

		set_addr_rw((unsigned long)ptr_modules_op, &pte_ro);
		ptr_modules_op->show = tpe_m_show;
		set_addr_ro((unsigned long)ptr_modules_op, pte_ro);
	}

	// hijack part of the kallsyms_operations symbol; it's a file_operations struct (not a pointer)

	ret = find_symbol_address(&sym_kallsyms_operations, "kallsyms_operations");

	if (IN_ERR(ret))
		printfail("kallsyms_operations");
	else {
		ptr_kallsyms_operations = sym_kallsyms_operations.addr;

		orig_kallsyms_open = ptr_kallsyms_operations->open;

		set_addr_rw((unsigned long)ptr_kallsyms_operations, &pte_ro);
		ptr_kallsyms_operations->open = tpe_kallsyms_open;
		set_addr_ro((unsigned long)ptr_kallsyms_operations, pte_ro);
	}
}

void undo_hijack_syscalls(void) {
	bool pte_ro;

	if (sym_security_ops.found) {
		ptr_security_ops->file_mmap = orig_security_file_mmap;
		ptr_security_ops->file_mprotect = orig_security_file_mprotect;
		ptr_security_ops->bprm_check_security = orig_bprm_check_security;
	}

	if (sym_pid_dentry_operations.found) {
		set_addr_rw((unsigned long)ptr_pid_dentry_operations, &pte_ro);
		ptr_pid_dentry_operations->d_revalidate = orig_pid_revalidate;
		set_addr_ro((unsigned long)ptr_pid_dentry_operations, pte_ro);
	}

	if (sym_proc_sys_file_operations.found) {
		set_addr_rw((unsigned long)ptr_proc_sys_file_operations, &pte_ro);
		ptr_proc_sys_file_operations->write = orig_proc_sys_write;
		set_addr_ro((unsigned long)ptr_proc_sys_file_operations, pte_ro);
	}

	if (sym_modules_op.found) {
		set_addr_rw((unsigned long)ptr_modules_op, &pte_ro);
		ptr_modules_op->show = orig_m_show;
		set_addr_ro((unsigned long)ptr_modules_op, pte_ro);
	}

	if (sym_kallsyms_operations.found) {
		set_addr_rw((unsigned long)ptr_kallsyms_operations, &pte_ro);
		ptr_kallsyms_operations->open = orig_kallsyms_open;
		set_addr_ro((unsigned long)ptr_kallsyms_operations, pte_ro);
	}
}

