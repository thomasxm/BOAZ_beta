//
// This is a GENERATED file. It should *not* be edited directly.
// Changes should be made to the defectdefs.xml file
// This file contains symbolic constants for warning numbers.
//


#pragma once

enum EConcurrencyCheckWarningCodes
{
    WARNING_RACE_CONDITION = 26100,                             // Race condition. Variable '%1$s' should be protected by lock '%2$s'.
    WARNING_INTERLOCKED_VIOLATION = 26101,                      // Failing to use interlocked operation properly for variable '%1$s'.
    WARNING_RACE_CONDITION_VIA_PARAMETER = 26102,               // Race condition through parameter access. Parameter '%1$s' is passed to a function and may be used to access variable '%2$s' which is guarded by lock '%3$s'. But this lock is not held and the callee does not guarantee to do so.
    WARNING_LOCKORDER_ACQUIRE_VIOLATION = 26105,                // Lock order violation. Acquiring lock '%1$s' with level %2$s causes order inversion.
    WARNING_LOCKORDER_RELEASE_VIOLATION = 26106,                // Lock order violation. Releasing lock '%1$s' with level %2$s causes order inversion.
    WARNING_CALLER_FAILING_TO_HOLD = 26110,                     // Caller failing to hold lock '%1$s' before calling function '%2$s'.
    WARNING_CALLER_FAILING_TO_RELEASE = 26111,                  // Caller failing to release lock '%1$s' before calling function '%2$s'.
    WARNING_CALLER_CANNOT_HOLD_ANY_LOCK = 26112,                // Caller cannot hold any lock before calling function '%1$s'.
    WARNING_FAILING_TO_RELEASE = 26115,                         // Failing to release lock '%1$s' in function '%2$s'.
    WARNING_FAILING_TO_ACQUIRE = 26116,                         // Failing to acquire or to hold lock '%1$s' in function '%2$s'.
    WARNING_RELEASING_UNHELD_LOCK = 26117,                      // Releasing unheld lock '%1$s' in function '%2$s'.
    WARNING_NEED_NO_COMPETING_THREAD = 26130,                   // Missing annotation _Requires_lock_held_(%1$s) or _No_competing_thread_ at function '%4$s'. Otherwise it could be a race condition. Variable '%2$s' should be protected by lock '%3$s'.
    WARNING_NEED_LOCKING_SIDE_EFFECT = 26135,                   // Missing annotation %1$s%2$s) at function '%3$s'.
    WARNING_NEED_GUARDED_BY = 26136,                            // Missing _Guarded_by_ annotation: variable '%2$s' is guarded by lock '%1$s'.
    WARNING_NEED_INTERLOCKED = 26137,                           // Missing annotation _Interlocked_ for variable %1$s.
    WARNING_SUSPENDED_WITH_LOCK = 26138,                        // Suspending a coroutine while holding lock %1$s.
    WARNING_CSAL_ANNOTATION_ERROR = 26140,                      // Undefined lock kind '%1$s' in annotation _Has_lock_kind_(%2$s) on lock '%3$s'.
    WARNING_CALLER_FAILING_TO_HOLD_MEDIUM_CONFIDENCE = 26160,   // Caller possibly failing to hold lock '%1$s' before calling function '%2$s'.
    WARNING_FAILING_TO_RELEASE_MEDIUM_CONFIDENCE = 26165,       // Possibly failing to release lock '%1$s' in function '%2$s'.
    WARNING_FAILING_TO_ACQUIRE_MEDIUM_CONFIDENCE = 26166,       // Possibly failing to acquire or to hold lock '%1$s' in function '%2$s'.
    WARNING_RELEASING_UNHELD_LOCK_MEDIUM_CONFIDENCE = 26167,    // Possibly releasing unheld lock '%1$s' in function '%2$s'.
};

#define ALL_CONCURRENCYCHECK_WARNINGS 26100 26101 26102 26105 26106 26110 26111 26112 26115 26116 26117 26130 26135 26136 26137 26138 26140 26160 26165 26166 26167

#define CONCURRENCYCHECK_DEFAULT_WARNINGS 26100 26101 26110 26111 26112 26115 26116 26117

#define CONCURRENCYCHECK_SECURITY_WARNINGS 26100 26101 26102 26105 26106 26110 26111 26112 26115 26116 26117 26130 26135 26136 26137 26160 26165 26166 26167
