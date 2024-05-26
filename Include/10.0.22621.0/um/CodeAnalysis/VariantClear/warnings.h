//
// This is a GENERATED file. It should *not* be edited directly.
// Changes should be made to the defectdefs.xml file
// This file contains symbolic constants for warning numbers.
//


#pragma once

enum EVariantClearWarningCodes
{
    WARNING_VARIANTCLEAR_UNINITIALIZED = 33001,         // VARIANT '%1$s' was cleared when it was uninitialized (expression '%2$s').
    WARNING_VARIANTCLEAR_MAYBEUNINITIALIZED = 33002,    // VARIANT '%1$s' was cleared when it may be uninitialized (expression '%2$s').
    WARNING_VARIANTCLEAR_LIKELYFALSEPOSITIVE = 33003,   // VARIANT '%1$s' is considered uninitialized but this is likely a false positive. If this is an array you should ignore this warning. (expression '%2$s').
    WARNING_VARIANTCLEAR_UNINITOUTPARAM = 33004,        // VARIANT '%1$s', which is marked as _Out_ was cleared before being initialized (expression '%2$s').
    WARNING_VARIANTCLEAR_UNINITFUNCPARAM = 33005,       // VARIANT '%1$s' was provided as an _In_ or _InOut_ parameter but was not initialized (expression '%2$s').
    WARNING_VARIANTCLEAR_NOSAL = 33006,                 // VARIANT '%1$s' was provided as a parameter without SAL and may have been cleared when it was not initialized. (expression '%2$s').
};

#define ALL_VARIANTCLEAR_WARNINGS 33001 33002 33003 33004 33005 33006
