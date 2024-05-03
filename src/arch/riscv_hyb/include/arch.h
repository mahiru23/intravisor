static __inline__ void * getSP(void) {
    register void * sp asm("sp");
    asm ("" : "=r"(sp));
    return sp;
}

static __inline__ void * getRA(void) {
    register void * sp asm("ra");
    asm ("" : "=r"(sp));
    return sp;
}

static __inline__ void * __capability getCSP(void) {
    register void * __capability sp asm("csp");
    asm ("" : "=r"(sp));
    return sp;
}

static __inline__ void * __capability getCT0(void) {
    register void * __capability ctp asm("ct0");
    asm ("" : "=C"(ctp));
    return ctp;
}

static __inline__ void * __capability getCT1(void) {
    register void * __capability ctp asm("ct1");
    asm ("" : "=C"(ctp));
    return ctp;
}

static __inline__ void * __capability getCA0(void) {
    register void * __capability ctp asm("ca0");
    asm ("" : "=C"(ctp));
    return ctp;
}

static __inline__ void * __capability getCA1(void) {
    register void * __capability ctp asm("ca1");
    asm ("" : "=C"(ctp));
    return ctp;
}

static __inline__ void * __capability getTP(void) {
    register void * __capability ctp asm("ctp");
    asm ("" : "=C"(ctp));
    return ctp;
}

#define __asm_syscall(...) \
	__asm__ __volatile__ ("ecall\n\t" \
	: "=r"(a0) : __VA_ARGS__ : "memory"); \
	return a0; \

static inline long __syscall3(long n, long a, long b, long c)
{
	register long t0 __asm__("t0") = n;
	register long a0 __asm__("a0") = a;
	register long a1 __asm__("a1") = b;
	register long a2 __asm__("a2") = c;
	__asm_syscall("r"(t0), "0"(a0), "r"(a1), "r"(a2))
}


static __inline__ long getT5(void) {
    register long t5 asm("t5");
    asm ("" : "=r"(t5));
    return t5;
}

static __inline__ void mv_sp(unsigned long sp) {
    	__asm__ __volatile__("mv sp, %0;" :: "r"(sp) : "memory");
		__asm__ __volatile__("CInvoke ct0, ct1;" ::  : "memory");
}

static __inline__ void cmv_ctp(void * __capability ctp) {
	__asm__ __volatile__("cmove ctp, %0;" :: "C"(ctp) : "memory");
}

static __inline__ void cmv_csp(void * __capability csp) {
	__asm__ __volatile__("cmove csp, %0;" :: "C"(csp) : "memory");
}

static __inline__ void test_resume_jump(void * __capability pcc, void * __capability ddc, void * __capability ddc2,unsigned long s0,unsigned long ra,unsigned long sp) {
	__asm__ __volatile__("cmove ct0, %0;" :: "C"(pcc) : "memory");
	__asm__ __volatile__("cmove ct1, %0;" :: "C"(ddc) : "memory");
	__asm__ __volatile__("cmove ct2, %0;" :: "C"(ddc2) : "memory");
	//__asm__ __volatile__("mv sp, %0;" :: "r"(sp) : "memory");

	//__asm__ __volatile__("cspecialw	ddc, ct2;" ::  : "memory");

	
	__asm__ __volatile__("mv ra, %0;" :: "r"(ra) : "memory");
	__asm__ __volatile__("mv sp, %0;" :: "r"(sp) : "memory");
	__asm__ __volatile__("mv s0, %0;" :: "r"(s0) : "memory");
	__asm__ __volatile__("cspecialw	ddc, ct2;" ::  : "memory");
	__asm__ __volatile__("CInvoke ct0, ct1;" ::  : "memory");
}
