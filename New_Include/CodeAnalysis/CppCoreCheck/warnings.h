//
// This is a GENERATED file. It should *not* be edited directly.
// Changes should be made to the defectdefs.xml file
// This file contains symbolic constants for warning numbers.
//


#pragma once

enum ECppCoreCheckWarningCodes
{
    WARNING_NO_RAW_POINTER_ASSIGNMENT = 26400,                                      // Do not assign the result of an allocation or a function call with an owner<T> return value to a raw pointer, use owner<T> instead (i.11).
    WARNING_DONT_DELETE_NON_OWNER = 26401,                                          // Do not delete a raw pointer that is not an owner<T> (i.11).
    WARNING_DONT_HEAP_ALLOCATE_MOVABLE_RESULT = 26402,                              // Return a scoped object instead of a heap-allocated if it has a move constructor (r.3).
    WARNING_RESET_OR_DELETE_OWNER = 26403,                                          // Reset or explicitly delete an owner<T> pointer '%1$s' (r.3).
    WARNING_DONT_DELETE_INVALID = 26404,                                            // Do not delete an owner<T> which may be in invalid state (r.3).
    WARNING_DONT_ASSIGN_TO_VALID = 26405,                                           // Do not assign to an owner<T> which may be in valid state (r.3).
    WARNING_DONT_ASSIGN_RAW_TO_OWNER = 26406,                                       // Do not assign a raw pointer to an owner<T> (r.3).
    WARNING_DONT_HEAP_ALLOCATE_UNNECESSARILY = 26407,                               // Prefer scoped objects, don't heap-allocate unnecessarily (r.5).
    WARNING_NO_MALLOC_FREE = 26408,                                                 // Avoid malloc() and free(), prefer the nothrow version of new with delete (r.10).
    WARNING_NO_NEW_DELETE = 26409,                                                  // Avoid calling new and delete explicitly, use std::make_unique<T> instead (r.11).
    WARNING_NO_REF_TO_CONST_UNIQUE_PTR = 26410,                                     // The parameter '%1$s' is a reference to const unique pointer, use const T* or const T& instead (r.32).
    WARNING_NO_REF_TO_UNIQUE_PTR = 26411,                                           // The parameter '%1$s' is a reference to unique pointer and it is never reassigned or reset, use T* or T& instead (r.33).
    WARNING_RESET_LOCAL_SMART_PTR = 26414,                                          // Move, copy, reassign or reset a local smart pointer '%1$s' (r.5).
    WARNING_SMART_PTR_NOT_NEEDED = 26415,                                           // Smart pointer parameter '%1$s' is used only to access contained pointer. Use T* or T& instead (r.30).
    WARNING_NO_RVALUE_REF_SHARED_PTR = 26416,                                       // Shared pointer parameter '%1$s' is passed by rvalue reference. Pass by value instead (r.34).
    WARNING_NO_LVALUE_REF_SHARED_PTR = 26417,                                       // Shared pointer parameter '%1$s' is passed by reference and not reset or reassigned. Use T* or T& instead (r.35).
    WARNING_NO_VALUE_OR_CONST_REF_SHARED_PTR = 26418,                               // Shared pointer parameter '%1$s' is not copied or moved. Use T* or T& instead (r.36).
    WARNING_NO_GLOBAL_INIT_CALLS = 26426,                                           // Global initializer calls a non-constexpr function '%1$s' (i.22).
    WARNING_NO_GLOBAL_INIT_EXTERNS = 26427,                                         // Global initializer accesses extern object '%1$s' (i.22).
    WARNING_USE_NOTNULL = 26429,                                                    // Symbol '%1$s' is never tested for nullness, it can be marked as not_null (f.23).
    WARNING_TEST_ON_ALL_PATHS = 26430,                                              // Symbol '%1$s' is not tested for nullness on all paths (f.23).
    WARNING_DONT_TEST_NOTNULL = 26431,                                              // The type of expression '%1$s' is already gsl::not_null. Do not test it for nullness (f.23).
    WARNING_DEFINE_OR_DELETE_SPECIAL_OPS = 26432,                                   // If you define or delete any default operation in the type '%1$s', define or delete them all (c.21).
    WARNING_NEED_VIRTUAL_DTOR = 26436,                                              // The type '%1$s' with a virtual function needs either public virtual or protected non-virtual destructor (c.35).
    WARNING_DONT_SLICE = 26437,                                                     // Do not slice (es.63).
    WARNING_NO_GOTO = 26438,                                                        // Avoid 'goto' (es.76).
    WARNING_SPECIAL_NOEXCEPT = 26439,                                               // This kind of function should not throw. Declare it 'noexcept' (f.6).
    WARNING_DECLARE_NOEXCEPT = 26440,                                               // Function '%1$s' can be declared 'noexcept' (f.6).
    WARNING_NO_UNNAMED_GUARDS = 26441,                                              // Guard objects must be named (cp.44).
    WARNING_NO_UNNAMED_RAII_OBJECTS = 26444,                                        // Don't try to declare a local variable with no name (es.84).
    WARNING_NO_SPAN_REF = 26445,                                                    // Do not assign gsl::span or std::string_view to a reference. They are cheap to construct and are not owners of the underlying data. (gsl.view).
    WARNING_USE_GSL_AT = 26446,                                                     // Prefer to use gsl::at() instead of unchecked subscript operator (bounds.4).
    WARNING_DONT_THROW_IN_NOEXCEPT = 26447,                                         // The function is declared 'noexcept' but calls function '%1$s()' which may throw exceptions (f.6).
    WARNING_USE_GSL_FINALLY = 26448,                                                // Consider using gsl::finally if final action is intended (gsl.util).
    WARNING_NO_SPAN_FROM_TEMPORARY = 26449,                                         // gsl::span or std::string_view created from a temporary will be invalid when the temporary is invalidated (gsl.view).
    WARNING_RESULT_OF_ARITHMETIC_OPERATION_PROVABLY_LOSSY = 26450,                  // Arithmetic overflow: '%1$s' operation causes overflow at compile time. Use a wider type to store the operands (io.1).
    WARNING_RESULT_OF_ARITHMETIC_OPERATION_CAST_TO_LARGER_SIZE = 26451,             // Arithmetic overflow: Using operator '%1$s' on a %2$d byte value and then casting the result to a %3$d byte value. Cast the value to the wider type before calling operator '%1$s' to avoid overflow (io.2).
    WARNING_SHIFT_COUNT_NEGATIVE_OR_TOO_BIG = 26452,                                // Arithmetic overflow: Left shift count is negative or greater than or equal to the operand size which is undefined behavior (io.3).
    WARNING_LEFTSHIFT_NEGATIVE_SIGNED_NUMBER = 26453,                               // Arithmetic overflow: Left shift of a negative signed number is undefined behavior (io.4).
    WARNING_RESULT_OF_ARITHMETIC_OPERATION_NEGATIVE_UNSIGNED = 26454,               // Arithmetic overflow: '%1$s' operation produces a negative unsigned result at compile time (io.5).
    WARNING_DEFAULT_CTOR_NOEXCEPT = 26455,                                          // Default constructor should not throw. Declare it 'noexcept' (f.6).
    WARNING_USE_STD_IGNORE_INSTEAD_OF_VOID_CAST = 26457,                            // (void) should not be used to ignore return values, use 'std::ignore =' instead (es.48).
    WARNING_PATH_SENSITIVE_USE_GSL_AT = 26458,                                      // Prefer to use gsl::at() instead of unchecked subscript operator (bounds.4).
    WARNING_NO_RAW_POINTER_IN_STL_RANGE_CHECKED = 26459,                            // You called an STL function '%s' with a raw pointer parameter at position '%d' that may be unsafe - this relies on the caller to check that the passed values are correct. Consider wrapping your range in a gsl::span and pass as a span iterator (stl.1).
    WARNING_USE_CONST_REFERENCE_ARGUMENTS = 26460,                                  // The reference argument '%s' for function '%s' can be marked as const (con.3).
    WARNING_USE_CONST_POINTER_ARGUMENTS = 26461,                                    // The pointer argument '%s' for function '%s' can be marked as a pointer to const (con.3).
    WARNING_USE_CONST_POINTER_FOR_VARIABLE = 26462,                                 // The value pointed to by '%1$s' is assigned only once, mark it as a pointer to const (con.4).
    WARNING_USE_CONST_FOR_ELEMENTS = 26463,                                         // The elements of array '%1$s' are assigned only once, mark elements const (con.4).
    WARNING_USE_CONST_POINTER_FOR_ELEMENTS = 26464,                                 // The values pointed to by elements of array '%1$s' are assigned only once, mark elements as pointer to const (con.4).
    WARNING_NO_CONST_CAST_NECESSARY = 26465,                                        // Don't use const_cast to cast away const or volatile. const_cast is not required; constness or volatility is not being removed by this conversion (type.3).
    WARNING_NO_STATIC_DOWNCAST_POLYMORPHIC = 26466,                                 // Don't use static_cast downcasts. A cast from a polymorphic type should use dynamic_cast (type.2).
    WARNING_AVOID_CAST_FLOAT_TO_UNSIGNED_INTEGER = 26467,                           // Converting from floating point to unsigned integral types results in non-portable code if the double/float has a negative value. Use gsl::narrow_cast or gsl::narrow instead to guard against undefined behavior and potential data loss (es.46).
    WARNING_NO_REINTERPRET_CAST_FROM_VOID_PTR = 26471,                              // Don't use reinterpret_cast. A cast from void* can use static_cast (type.1).
    WARNING_NO_CASTS_FOR_ARITHMETIC_CONVERSION = 26472,                             // Don't use a static_cast for arithmetic conversions. Use brace initialization, gsl::narrow_cast or gsl::narrow (type.1).
    WARNING_NO_IDENTITY_CAST = 26473,                                               // Don't cast between pointer types where the source type and the target type are the same (type.1).
    WARNING_NO_IMPLICIT_CAST = 26474,                                               // Don't cast between pointer types when the conversion could be implicit (type.1).
    WARNING_NO_FUNCTION_STYLE_CASTS = 26475,                                        // Do not use function style casts (es.49). Prefer 'Type{value}' over 'Type(value)'..
    WARNING_USE_VARIANT = 26476,                                                    // Expression/symbol '%s' uses a naked union '%s' with multiple type pointers: Use variant instead (type.7).
    WARNING_USE_NULLPTR_NOT_CONSTANT = 26477,                                       // Use 'nullptr' rather than 0 or NULL (es.47).
    WARNING_NO_MOVE_OP_ON_CONST = 26478,                                            // Don't use std::move on constant variables. (es.56).
    WARNING_NO_MOVE_RET_ON_LOCALS = 26479,                                          // Don't use std::move to return a local variable. (f.48).
    WARNING_NO_POINTER_ARITHMETIC = 26481,                                          // Don't use pointer arithmetic. Use span instead (bounds.1).
    WARNING_NO_DYNAMIC_ARRAY_INDEXING = 26482,                                      // Only index into arrays using constant expressions (bounds.2).
    WARNING_STATIC_INDEX_OUT_OF_RANGE = 26483,                                      // Value %1$lld is outside the bounds (0, %2$lld) of variable '%3$s'. Only index into arrays using constant expressions that are within bounds of the array (bounds.2).
    WARNING_NO_ARRAY_TO_POINTER_DECAY = 26485,                                      // Expression '%1$s': No array to pointer decay (bounds.3).
    WARNING_LIFETIMES_FUNCTION_PRECONDITION_VIOLATION = 26486,                      // Don't pass a pointer that may be invalid to a function. Parameter %1$d '%2$s' in call to '%3$s' may be invalid (lifetime.3).
    WARNING_LIFETIMES_FUNCTION_POSTCONDITION_VIOLATION = 26487,                     // Don't return a pointer '%1$s' that may be invalid (lifetime.4).
    WARNING_LIFETIMES_DEREF_NULL_POINTER = 26488,                                   // Do not dereference a potentially null pointer: '%1$s'. '%2$s' was null at line %3$u (lifetime.1).
    WARNING_LIFETIMES_DEREF_INVALID_POINTER = 26489,                                // Don't dereference a pointer that may be invalid: '%1$s'. '%2$s' may have been invalidated at line %3$u (lifetime.1).
    WARNING_NO_REINTERPRET_CAST = 26490,                                            // Don't use reinterpret_cast (type.1).
    WARNING_NO_STATIC_DOWNCAST = 26491,                                             // Don't use static_cast downcasts (type.2).
    WARNING_NO_CONST_CAST = 26492,                                                  // Don't use const_cast to cast away const or volatile (type.3).
    WARNING_NO_CSTYLE_CAST = 26493,                                                 // Don't use C-style casts (type.4).
    WARNING_VAR_USE_BEFORE_INIT = 26494,                                            // Variable '%1$s' is uninitialized. Always initialize an object (type.5).
    WARNING_MEMBER_UNINIT = 26495,                                                  // Variable '%1$s' is uninitialized. Always initialize a member variable (type.6).
    WARNING_USE_CONST_FOR_VARIABLE = 26496,                                         // The variable '%1$s' does not change after construction, mark it as const (con.4).
    WARNING_USE_CONSTEXPR_FOR_FUNCTION = 26497,                                     // You can attempt to make '%1$s' constexpr unless it contains any undefined behavior (f.4).
    WARNING_USE_CONSTEXPR_FOR_FUNCTIONCALL = 26498,                                 // The function '%1$s' is constexpr, mark variable '%2$s' constexpr if compile-time evaluation is desired (con.5).
    WARNING_USE_OF_A_MOVED_FROM_OBJECT = 26800,                                     // Use of a moved from object: ''%1$s'' (lifetime.1).
    WARNING_COROUTINES_USE_AFTER_FREE_CAPTURE = 26810,                              // Lifetime of captured variable ''%1$s'' might end by the time the coroutine is resumed (lifetime.1).
    WARNING_COROUTINES_USE_AFTER_FREE_PARAM = 26811,                                // Lifetime of the memory referenced by parameter ''%1$s'' might end by the time the coroutine is resumed (lifetime.1).
    WARNING_USE_BITWISE_AND_TO_CHEK_ENUM_FLAGS = 26813,                             // Use 'bitwise and' to check if a flag is set.
    WARNING_USE_CONSTEXPR_RATHER_THAN_CONST = 26814,                                // The const variable '%1$s' can be computed at compile-time. Consider using constexpr (con.5).
    WARNING_LIFETIME_LOCAL_USE_AFTER_FREE_TEMP = 26815,                             // The pointer is dangling because it points at a temporary instance which was destroyed.
    WARNING_LIFETIME_LOCAL_USE_AFTER_FREE_STACK = 26816,                            // The pointer points to memory allocated on the stack.
    WARNING_RANGE_FOR_UNNECESSARY_COPY = 26817,                                     // Potentially expensive copy of variable '%1$s' in range-for loop. Consider making it a const reference (es.71).
    WARNING_NON_ENUM_SWITCH_MISSING_DEFAULT = 26818,                                // Switch statement does not cover all cases. Consider adding a 'default' label (es.79).
    WARNING_UNANNOTATED_SWITCH_FALLTHROUGH = 26819,                                 // Unannotated fallthrough between switch labels (es.78).
    WARNING_CHANGE_AUTO_TO_REFERENCE = 26820,                                       // This is a potentially expensive copy operation. Consider using a reference unless a copy is required (p.9).
    WARNING_USE_GSL_SPAN_OVER_STD_SPAN = 26821,                                     // For '%1$s', consider using gsl::span instead of std::span to guarantee runtime bounds safety (gsl.view).
    WARNING_NULLPTR_DEREFERENCE = 26822,                                            // Dereferencing a null pointer '%1$s' (lifetime.1).
    WARNING_NULLPTR_DEREFERENCE_MAYBE = 26823,                                      // Dereferencing a possibly null pointer '%1$s' (lifetime.1).
    WARNING_NULLPTR_POSTCONDITION_VIOLATION = 26824,                                // Postcondition for null pointer '%1$s' requires it to be non-null (lifetime.1).
    WARNING_NULLPTR_POSTCONDITION_VIOLATION_MAYBE = 26825,                          // Postcondition for possibly null pointer '%1$s' requires it to be non-null (lifetime.1).
    WARNING_DONT_USE_VA_ARGS = 26826,                                               // Don't use C-style variable arguments (f.55).
    WARNING_ALMOST_BITWISE_ENUM = 26827,                                            // Did you forget to initialize an enum constant, or intend to use another type?.
    WARNING_MIXING_OVERLAPPING_ENUMS = 26828,                                       // Different enum types have overlapping values. Did you want to use another enum constant here?.
    WARNING_UNWRAP_EMPTY_OPTIONAL = 26829,                                          // Empty optional ''%1$s'' is unwrapped.
    WARNING_UNWRAP_EMPTY_OPTIONAL_MAYBE = 26830,                                    // Potentially empty optional ''%1$s'' is unwrapped.
    WARNING_DEAD_STORE = 26834,                                                     // Variable '%1$s' is assigned a value that is never read.
    WARNING_DEAD_STORE_AT_DECLARATION = 26836,                                      // Variable '%1$s' is assigned a value that is never read at declaration.
    WARNING_LIFETIMES_FUNCTION_PRECONDITION_VIOLATION_HIGH_CONFIDENCE = 26846,      // Don't pass an invalid pointer to a function. Parameter %1$d '%2$s' in call to '%3$s' is invalid (lifetime.3).
    WARNING_LIFETIMES_FUNCTION_POSTCONDITION_VIOLATION_HIGH_CONFIDENCE = 26847,     // Don't return an invalid pointer '%1$s' (lifetime.4).
    WARNING_LIFETIMES_DEREF_NULL_POINTER_HIGH_CONFIDENCE = 26848,                   // Do not dereference a null pointer: '%1$s'. '%2$s' was null at line %3$u (lifetime.1).
    WARNING_LIFETIMES_DEREF_INVALID_POINTER_HIGH_CONFIDENCE = 26849,                // Don't dereference an invalid pointer: '%1$s'. '%2$s' have been invalidated at line %3$u (lifetime.1).
    WARNING_DONT_ASSIGN_RAW_POINTER_TO_OWNER = 26850,                               // Do not assign a raw pointer '%2$s' to an owner<T> '%1$s' (ownership.1).
    WARNING_SHOULD_MARK_AS_OWNER = 26851,                                           // Variable '%1$s' has ownership on heap memory, should be marked as owner<T> (ownership.2).
    WARNING_SHOULD_NOT_RESEAT_ACTIVE_OWNER = 26852,                                 // Variable '%1$s' has ownership on heap memory already. Please transfer or free the owned memory first. (ownership.3).
    WARNING_DONT_DELETE_RAW_POINTER = 26853,                                        // Do not delete a raw pointer that is not an owner<T> (ownership.4).
    WARNING_DONT_USE_INVALID_OWNER = 26854,                                         // Transferring/freeing owner '%1$s' which has previously transferred ownership or points to garbage (ownership.5).
    WARNING_RELEASE_OWNED_MEMORY = 26855,                                           // Owner '%1$s' is going out of scope, please transfer its ownership or free its owned memory (ownership.6).
    WARNING_DONT_ASSIGN_RAW_POINTER_TO_OWNER_PARAMETER = 26856,                     // Raw pointer '%1$s' is used as an owner argument (ownership.7).
    WARNING_SHOULD_MARK_AS_OWNER_IN_FUNCTION_SIGNATURE = 26857,                     // Mark the raw pointers in the target function signature as owners if you expect to send or return heap allocated objects. (ownership.8).
    WARNING_SHOULD_ACQUIRE_OWNERSHIP = 26858,                                       // Expected owner pointer '%1$s' to have ownership at the end of the function (ownership.9).
    WARNING_UNWRAP_EMPTY_OPTIONAL_VALUE = 26859,                                    // Empty optional ''%1$s'' is unwrapped, will throw exception.
    WARNING_UNWRAP_EMPTY_OPTIONAL_VALUE_MAYBE = 26860,                              // Potentially empty optional ''%1$s'' is unwrapped, may throw exception.
    WARNING_DATETIME_MANIPULATION_WITHOHUT_LEAPYEAR_CHECK = 26861,                  // Field of a date-time object '%1$s' has been modified without proper leap year checking: '%2$s'.
    WARNING_INCOMPLETE_DATETIME_CONVERSION = 26862,                                 // A date-time object '%1$s' has been created from a different type of date-time object but conversion was incomplete: '%2$s'.
    WARNING_DATETIME_MANIPULATION_FUNCTION_RETURN_IGNORED = 26863,                  // Return value from a date-time handling function '%1$s' is ignored.
    WARNING_DATETIME_MANIPULATION_ASSUMING_365_DAYS_WITHOUT_LEAPYEAR_CHECK = 26864, // Day field of a date-time object '%1$s' has been modified assuming 365 days per year without proper leap year checking: '%2$s'.
};

#define ALL_CPPCORECHECK_WARNINGS 26400 26401 26402 26403 26404 26405 26406 26407 26408 26409 26410 26411 26414 26415 26416 26417 26418 26426 26427 26429 26430 26431 26432 26436 26437 26438 26439 26440 26441 26444 26445 26446 26447 26448 26449 26450 26451 26452 26453 26454 26455 26457 26458 26459 26460 26461 26462 26463 26464 26465 26466 26467 26471 26472 26473 26474 26475 26476 26477 26478 26479 26481 26482 26483 26485 26486 26487 26488 26489 26490 26491 26492 26493 26494 26495 26496 26497 26498 26800 26810 26811 26813 26814 26815 26816 26817 26818 26819 26820 26821 26822 26823 26824 26825 26826 26827 26828 26829 26830 26834 26836 26846 26847 26848 26849 26850 26851 26852 26853 26854 26855 26856 26857 26858 26859 26860 26861 26862 26863 26864

#define CPPCORECHECK_ARITHMETIC_WARNINGS 26450 26451 26452 26453 26454

#define CPPCORECHECK_BOUNDS_WARNINGS 26446 26458 26459 26481 26482 26483 26485

#define CPPCORECHECK_CLASS_WARNINGS 26432 26436

#define CPPCORECHECK_CONCURRENCY_WARNINGS 26441

#define CPPCORECHECK_CONST_WARNINGS 26460 26461 26462 26463 26464 26496 26497 26498 26814

#define CPPCORECHECK_DECLARATION_WARNINGS 26426 26427 26444 26817 26820

#define CPPCORECHECK_DEFAULT_WARNINGS 26437 26441 26444 26449 26450 26451 26452 26453 26454 26495

#define CPPCORECHECK_ENUM_WARNINGS 26813 26827 26828

#define CPPCORECHECK_FUNCTION_WARNINGS 26439 26440 26447 26455

#define CPPCORECHECK_GSL_WARNINGS 26445 26446 26448 26449 26458

#define CPPCORECHECK_LIFETIME_WARNINGS 26486 26487 26488 26489 26800 26810 26811 26815 26816 26822 26823 26824 26825 26846 26847 26848 26849

#define CPPCORECHECK_OWNER_POINTER_WARNINGS 26402 26403 26404 26405 26406 26407 26429 26430 26431

#define CPPCORECHECK_RAW_POINTER_WARNINGS 26400 26401 26402 26408 26409 26429 26430 26431 26481 26485

#define CPPCORECHECK_SECURITY_WARNINGS 26426 26427 26437 26441 26444 26449 26450 26451 26452 26453 26454 26459 26466 26471 26472 26475 26476 26481 26482 26483 26485 26486 26487 26489 26490 26491 26492 26493 26494 26495 26800 26810 26811 26846 26847 26849

#define CPPCORECHECK_SHARED_POINTER_WARNINGS 26414 26415 26416 26417 26418

#define CPPCORECHECK_STL_WARNINGS 26459

#define CPPCORECHECK_STYLE_WARNINGS 26438 26818 26819

#define CPPCORECHECK_TYPE_WARNINGS 26437 26465 26466 26467 26471 26472 26473 26474 26475 26476 26477 26478 26479 26490 26491 26492 26493 26494 26495 26826

#define CPPCORECHECK_UNIQUE_POINTER_WARNINGS 26410 26411 26414 26415
