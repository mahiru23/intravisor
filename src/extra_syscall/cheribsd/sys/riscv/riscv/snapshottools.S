

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

#if __has_feature(capabilities)

#ifndef __CHERI_PURE_CAPABILITY__
	ld a1, (STEP_LEN * 33)(a0)
	csrw sstatus, a1
	lc ca1, (STEP_LEN * 32)(a0)
	cspecialw ddc, ca1
	lc ca1, (STEP_LEN * 31)(a0)
	cspecialw sepcc, ca1

	lc cra, (STEP_LEN * 0)(a0)
	lc csp, (STEP_LEN * 1)(a0)
	lc cgp, (STEP_LEN * 2)(a0)
	lc ctp, (STEP_LEN * 3)(a0)

	lc ct0, (STEP_LEN * 4)(a0)
	lc ct1, (STEP_LEN * 5)(a0)
	lc ct2, (STEP_LEN * 6)(a0)
	lc ct3, (STEP_LEN * 7)(a0)
	lc ct4, (STEP_LEN * 8)(a0)
	lc ct5, (STEP_LEN * 9)(a0)
	lc ct6, (STEP_LEN * 10)(a0)

	lc cs0, (STEP_LEN * 11)(a0)
	lc cs1, (STEP_LEN * 12)(a0)
	lc cs2, (STEP_LEN * 13)(a0)
	lc cs3, (STEP_LEN * 14)(a0)
	lc cs4, (STEP_LEN * 15)(a0)
	lc cs5, (STEP_LEN * 16)(a0)
	lc cs6, (STEP_LEN * 17)(a0)
	lc cs7, (STEP_LEN * 18)(a0)
	lc cs8, (STEP_LEN * 19)(a0)
	lc cs9, (STEP_LEN * 20)(a0)
	lc cs10, (STEP_LEN * 21)(a0)
	lc cs11, (STEP_LEN * 22)(a0)

	lc ca1, (STEP_LEN * 24)(a0)
	lc ca2, (STEP_LEN * 25)(a0)
	lc ca3, (STEP_LEN * 26)(a0)
	lc ca4, (STEP_LEN * 27)(a0)
	lc ca5, (STEP_LEN * 28)(a0)
	lc ca6, (STEP_LEN * 29)(a0)
	lc ca7, (STEP_LEN * 30)(a0)

	lc ca0, (STEP_LEN * 23)(a0)

	sret
#else
	sret
#endif

#else
	ld ra, (STEP_LEN * 0)(a0)
#endif

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
