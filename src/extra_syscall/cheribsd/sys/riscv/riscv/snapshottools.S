

#include "assym.inc"
#include "opt_sched.h"

#include <machine/param.h>
#include <machine/asm.h>
#include <machine/riscvreg.h>
#include <machine/pte.h>

__FBSDID("$FreeBSD$");

#define STEP_LEN 16
/*
 * void recover_snapshot(struct trapframe *frame)
 *
 */
ENTRY(recover_snapshot)

	/* Restore sstatus */
#ifdef __CHERI_PURE_CAPABILITY__
	cld	t0, (STEP_LEN * 33)(ca0)
#else
	ld	t0, (STEP_LEN * 33)(a0)
#endif

	csrw	sstatus, t0

#if __has_feature(capabilities)


#ifndef __CHERI_PURE_CAPABILITY__
.option push
.option capmode
#endif

	cspecialr ct0, ddc
	csetaddr ct0, ct0, a0
	cmove	ca0, ct0


	clc ca1, (STEP_LEN * 31)(ca0)
	cspecialw sepcc, ca1

	clc cra, (STEP_LEN * 0)(ca0)
	clc csp, (STEP_LEN * 1)(ca0)
	clc cgp, (STEP_LEN * 2)(ca0)
	clc ctp, (STEP_LEN * 3)(ca0)

	clc ct0, (STEP_LEN * 4)(ca0)
	clc ct1, (STEP_LEN * 5)(ca0)
	clc ct2, (STEP_LEN * 6)(ca0)
	clc ct3, (STEP_LEN * 7)(ca0)
	clc ct4, (STEP_LEN * 8)(ca0)
	clc ct5, (STEP_LEN * 9)(ca0)
	clc ct6, (STEP_LEN * 10)(ca0)

	clc cs0, (STEP_LEN * 11)(ca0)
	clc cs1, (STEP_LEN * 12)(ca0)
	clc cs2, (STEP_LEN * 13)(ca0)
	clc cs3, (STEP_LEN * 14)(ca0)
	clc cs4, (STEP_LEN * 15)(ca0)
	clc cs5, (STEP_LEN * 16)(ca0)
	clc cs6, (STEP_LEN * 17)(ca0)
	clc cs7, (STEP_LEN * 18)(ca0)
	clc cs8, (STEP_LEN * 19)(ca0)
	clc cs9, (STEP_LEN * 20)(ca0)
	clc cs10, (STEP_LEN * 21)(ca0)
	clc cs11, (STEP_LEN * 22)(ca0)

	clc ca1, (STEP_LEN * 24)(ca0)
	clc ca2, (STEP_LEN * 25)(ca0)
	clc ca3, (STEP_LEN * 26)(ca0)
	clc ca4, (STEP_LEN * 27)(ca0)
	clc ca5, (STEP_LEN * 28)(ca0)
	clc ca6, (STEP_LEN * 29)(ca0)
	clc ca7, (STEP_LEN * 30)(ca0)

	/*clc ca0, (STEP_LEN * 23)(ca0)*/

	clc ca1, (STEP_LEN * 32)(ca0)
	cspecialw ddc, ca1

#ifndef __CHERI_PURE_CAPABILITY__
.option pop
#endif


#else


	ld a1, (STEP_LEN * 31)(a0)
	cspecialw sepc, a1

	ld ra, (STEP_LEN * 0)(a0)
	ld sp, (STEP_LEN * 1)(a0)
	ld gp, (STEP_LEN * 2)(a0)
	ld tp, (STEP_LEN * 3)(a0)

	ld t0, (STEP_LEN * 4)(a0)
	ld t1, (STEP_LEN * 5)(a0)
	ld t2, (STEP_LEN * 6)(a0)
	ld t3, (STEP_LEN * 7)(a0)
	ld t4, (STEP_LEN * 8)(a0)
	ld t5, (STEP_LEN * 9)(a0)
	ld t6, (STEP_LEN * 10)(a0)

	ld s0, (STEP_LEN * 11)(a0)
	ld s1, (STEP_LEN * 12)(a0)
	ld s2, (STEP_LEN * 13)(a0)
	ld s3, (STEP_LEN * 14)(a0)
	ld s4, (STEP_LEN * 15)(a0)
	ld s5, (STEP_LEN * 16)(a0)
	ld s6, (STEP_LEN * 17)(a0)
	ld s7, (STEP_LEN * 18)(a0)
	ld s8, (STEP_LEN * 19)(a0)
	ld s9, (STEP_LEN * 20)(a0)
	ld s10, (STEP_LEN * 21)(a0)
	ld s11, (STEP_LEN * 22)(a0)

	ld a1, (STEP_LEN * 24)(a0)
	ld a2, (STEP_LEN * 25)(a0)
	ld a3, (STEP_LEN * 26)(a0)
	ld a4, (STEP_LEN * 27)(a0)
	ld a5, (STEP_LEN * 28)(a0)
	ld a6, (STEP_LEN * 29)(a0)
	ld a7, (STEP_LEN * 30)(a0)

	ld a0, (STEP_LEN * 23)(a0)

#endif

	sret



END(recover_snapshot)




/*
 * CHERI CHANGES START
 * {
 *   "updated": 20200804,
 *   "target_type": "kernel",
 *   "changes_purecap": [
 *     "support"
 *   ]
 * }
 * CHERI CHANGES END
 */
