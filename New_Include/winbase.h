/*
 * winbase.h
 *
 * Windows API Base Definitions
 *
 * $Id: winbase.h,v 1477b9ccd964 2017/05/31 13:21:20 keithmarshall $
 *
 * Written by Anders Norlander <anorland@hem2.passagen.se>
 * Copyright (C) 1998-2012, 2016, 2017, MinGW.org Project.
 *
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */
#ifndef _WINBASE_H
#pragma GCC system_header
#define _WINBASE_H

#ifdef __GNUC__
# define __GNUC_EXTENSION  __extension__
#else
# define __GNUC_EXTENSION
#endif

#ifndef WINBASEAPI
# ifdef __W32API_USE_DLLIMPORT__
#  define WINBASEAPI  DECLSPEC_IMPORT
# else
#  define WINBASEAPI
# endif
#endif

#ifndef WINADVAPI
# ifdef __W32API_USE_DLLIMPORT__
#  define WINADVAPI  DECLSPEC_IMPORT
# else
#  define WINADVAPI
# endif
#endif

/* To make <winbase.h> effectively self-contained, we must ensure
 * that both <stdarg.h> and <windef.h> are included beforehand.
 */
#include <stdarg.h>
#include <windef.h>

_BEGIN_C_DECLS

#define SP_SERIALCOMM						       1

#define PST_UNSPECIFIED 					       0
#define PST_RS232						       1
#define PST_PARALLELPORT					       2
#define PST_RS422						       3
#define PST_RS423						       4
#define PST_RS449						       5
#define PST_MODEM						       6
#define PST_FAX 						    0x21
#define PST_SCANNER						    0x22
#define PST_NETWORK_BRIDGE					   0x100
#define PST_LAT 						   0x101
#define PST_TCPIP_TELNET					   0x102
#define PST_X25 						   0x103

#define BAUD_075						       1
#define BAUD_110						       2
#define BAUD_134_5						       4
#define BAUD_150						       8
#define BAUD_300						      16
#define BAUD_600						      32
#define BAUD_1200						      64
#define BAUD_1800						     128
#define BAUD_2400						     256
#define BAUD_4800						     512
#define BAUD_7200						    1024
#define BAUD_9600						    2048
#define BAUD_14400						    4096
#define BAUD_19200						    8192
#define BAUD_38400						   16384
#define BAUD_56K						   32768
#define BAUD_128K						   65536
#define BAUD_115200						  131072
#define BAUD_57600						  262144
#define BAUD_USER					      0x10000000

#define PCF_DTRDSR						       1
#define PCF_RTSCTS						       2
#define PCF_RLSD						       4
#define PCF_PARITY_CHECK					       8
#define PCF_XONXOFF						      16
#define PCF_SETXCHAR						      32
#define PCF_TOTALTIMEOUTS					      64
#define PCF_INTTIMEOUTS 					     128
#define PCF_SPECIALCHARS					     256
#define PCF_16BITMODE						     512

#define SP_PARITY						       1
#define SP_BAUD 						       2
#define SP_DATABITS						       4
#define SP_STOPBITS						       8
#define SP_HANDSHAKING						      16
#define SP_PARITY_CHECK 					      32
#define SP_RLSD 						      64

#define DATABITS_5						       1
#define DATABITS_6						       2
#define DATABITS_7						       4
#define DATABITS_8						       8
#define DATABITS_16						      16
#define DATABITS_16X						      32

#define STOPBITS_10						       1
#define STOPBITS_15						       2
#define STOPBITS_20						       4

#define PARITY_NONE						     256
#define PARITY_ODD						     512
#define PARITY_EVEN						    1024
#define PARITY_MARK						    2048
#define PARITY_SPACE						    4096

#define EXCEPTION_DEBUG_EVENT					       1
#define CREATE_THREAD_DEBUG_EVENT				       2
#define CREATE_PROCESS_DEBUG_EVENT				       3
#define EXIT_THREAD_DEBUG_EVENT 				       4
#define EXIT_PROCESS_DEBUG_EVENT				       5
#define LOAD_DLL_DEBUG_EVENT					       6
#define UNLOAD_DLL_DEBUG_EVENT					       7
#define OUTPUT_DEBUG_STRING_EVENT				       8
#define RIP_EVENT						       9

#define HFILE_ERROR					     ((HFILE)(-1))

#define FILE_BEGIN						       0
#define FILE_CURRENT						       1
#define FILE_END						       2

#define INVALID_SET_FILE_POINTER			     ((DWORD)(-1))

#define OF_READ 						       0
#define OF_READWRITE						       2
#define OF_WRITE						       1
#define OF_SHARE_COMPAT 					       0
#define OF_SHARE_DENY_NONE					      64
#define OF_SHARE_DENY_READ					      48
#define OF_SHARE_DENY_WRITE					      32
#define OF_SHARE_EXCLUSIVE					      16
#define OF_CANCEL						    2048
#define OF_CREATE						    4096
#define OF_DELETE						     512
#define OF_EXIST						   16384
#define OF_PARSE						     256
#define OF_PROMPT						    8192
#define OF_REOPEN						   32768
#define OF_VERIFY						    1024

#define NMPWAIT_NOWAIT						       1
#define NMPWAIT_WAIT_FOREVER				     ((DWORD)(-1))
#define NMPWAIT_USE_DEFAULT_WAIT				       0

#define CE_BREAK						      16
#define CE_DNS							    2048
#define CE_FRAME						       8
#define CE_IOE							    1024
#define CE_MODE 						   32768
#define CE_OOP							    4096
#define CE_OVERRUN						       2
#define CE_PTO							     512
#define CE_RXOVER						       1
#define CE_RXPARITY						       4
#define CE_TXFULL						     256

#define PROGRESS_CONTINUE					       0
#define PROGRESS_CANCEL 					       1
#define PROGRESS_STOP						       2
#define PROGRESS_QUIET						       3

#define CALLBACK_CHUNK_FINISHED 				       0
#define CALLBACK_STREAM_SWITCH					       1

#define COPY_FILE_FAIL_IF_EXISTS				  0x0001
#define COPY_FILE_RESTARTABLE					  0x0002
#define COPY_FILE_OPEN_SOURCE_FOR_WRITE 			  0x0004

#define OFS_MAXPATHNAME 					     128

#define FILE_MAP_ALL_ACCESS					 0xF001F
#define FILE_MAP_READ						       4
#define FILE_MAP_WRITE						       2
#define FILE_MAP_COPY						       1

#define MUTEX_ALL_ACCESS					0x1F0001
#define MUTEX_MODIFY_STATE					       1

#define SEMAPHORE_ALL_ACCESS					0x1F0003
#define SEMAPHORE_MODIFY_STATE					       2

#define EVENT_ALL_ACCESS					0x1F0003
#define EVENT_MODIFY_STATE					       2

#define PIPE_ACCESS_DUPLEX					       3
#define PIPE_ACCESS_INBOUND					       1
#define PIPE_ACCESS_OUTBOUND					       2
#define PIPE_TYPE_BYTE						       0
#define PIPE_TYPE_MESSAGE					       4
#define PIPE_READMODE_BYTE					       0
#define PIPE_READMODE_MESSAGE					       2
#define PIPE_WAIT						       0
#define PIPE_NOWAIT						       1
#define PIPE_CLIENT_END 					       0
#define PIPE_SERVER_END 					       1
#define PIPE_UNLIMITED_INSTANCES				     255

#define DEBUG_PROCESS					      0x00000001
#define DEBUG_ONLY_THIS_PROCESS 			      0x00000002
#define CREATE_SUSPENDED				      0x00000004
#define DETACHED_PROCESS				      0x00000008
#define CREATE_NEW_CONSOLE				      0x00000010
#define NORMAL_PRIORITY_CLASS				      0x00000020
#define IDLE_PRIORITY_CLASS				      0x00000040
#define HIGH_PRIORITY_CLASS				      0x00000080
#define REALTIME_PRIORITY_CLASS 			      0x00000100
#define CREATE_NEW_PROCESS_GROUP			      0x00000200
#define CREATE_UNICODE_ENVIRONMENT			      0x00000400
#define CREATE_SEPARATE_WOW_VDM 			      0x00000800
#define CREATE_SHARED_WOW_VDM				      0x00001000
#define CREATE_FORCEDOS 				      0x00002000
#define BELOW_NORMAL_PRIORITY_CLASS			      0x00004000
#define ABOVE_NORMAL_PRIORITY_CLASS			      0x00008000
#define STACK_SIZE_PARAM_IS_A_RESERVATION		      0x00010000
#define CREATE_BREAKAWAY_FROM_JOB			      0x01000000
#define CREATE_WITH_USERPROFILE 			      0x02000000
#define CREATE_DEFAULT_ERROR_MODE			      0x04000000
#define CREATE_NO_WINDOW				      0x08000000

#define PROFILE_USER					      0x10000000
#define PROFILE_KERNEL					      0x20000000
#define PROFILE_SERVER					      0x40000000

#define CONSOLE_TEXTMODE_BUFFER 				       1

#define CREATE_NEW						       1
#define CREATE_ALWAYS						       2
#define OPEN_EXISTING						       3
#define OPEN_ALWAYS						       4
#define TRUNCATE_EXISTING					       5

#define FILE_FLAG_WRITE_THROUGH 			      0x80000000
#define FILE_FLAG_OVERLAPPED				      1073741824
#define FILE_FLAG_NO_BUFFERING				       536870912
#define FILE_FLAG_RANDOM_ACCESS 			       268435456
#define FILE_FLAG_SEQUENTIAL_SCAN			       134217728
#define FILE_FLAG_DELETE_ON_CLOSE				67108864
#define FILE_FLAG_BACKUP_SEMANTICS				33554432
#define FILE_FLAG_POSIX_SEMANTICS				16777216
#define FILE_FLAG_OPEN_REPARSE_POINT				 2097152
#define FILE_FLAG_OPEN_NO_RECALL				 1048576

#define SYMBOLIC_LINK_FLAG_DIRECTORY				     0x1

#define CLRDTR							       6
#define CLRRTS							       4
#define SETDTR							       5
#define SETRTS							       3
#define SETXOFF 						       1
#define SETXON							       2
#define SETBREAK						       8
#define CLRBREAK						       9

#define STILL_ACTIVE						   0x103

#define FIND_FIRST_EX_CASE_SENSITIVE				       1

#define SCS_32BIT_BINARY					       0
#define SCS_64BIT_BINARY					       6
#define SCS_DOS_BINARY						       1
#define SCS_OS216_BINARY					       5
#define SCS_PIF_BINARY						       3
#define SCS_POSIX_BINARY					       4
#define SCS_WOW_BINARY						       2

#define MAX_COMPUTERNAME_LENGTH 				      15

#define HW_PROFILE_GUIDLEN					      39
#define MAX_PROFILE_LEN 					      80

#define DOCKINFO_UNDOCKED					       1
#define DOCKINFO_DOCKED 					       2
#define DOCKINFO_USER_SUPPLIED					       4
#define DOCKINFO_USER_UNDOCKED	      (DOCKINFO_USER_SUPPLIED|DOCKINFO_UNDOCKED)
#define DOCKINFO_USER_DOCKED	       (DOCKINFO_USER_SUPPLIED|DOCKINFO_DOCKED)

#define DRIVE_REMOVABLE 					       2
#define DRIVE_FIXED						       3
#define DRIVE_REMOTE						       4
#define DRIVE_CDROM						       5
#define DRIVE_RAMDISK						       6
#define DRIVE_UNKNOWN						       0
#define DRIVE_NO_ROOT_DIR					       1

#define FILE_TYPE_UNKNOWN					       0
#define FILE_TYPE_DISK						       1
#define FILE_TYPE_CHAR						       2
#define FILE_TYPE_PIPE						       3
#define FILE_TYPE_REMOTE					  0x8000
#define FILE_ENCRYPTABLE					       0
#define FILE_IS_ENCRYPTED					       1
#define FILE_READ_ONLY						       8
#define FILE_ROOT_DIR						       3
#define FILE_SYSTEM_ATTR					       2
#define FILE_SYSTEM_DIR 					       4
#define FILE_SYSTEM_NOT_SUPPORT 				       6
#define FILE_UNKNOWN						       5
#define FILE_USER_DISALLOWED					       7

/* also in ddk/ntapi.h */
#define HANDLE_FLAG_INHERIT					    0x01
#define HANDLE_FLAG_PROTECT_FROM_CLOSE				    0x02
/* end ntapi.h */

#define STD_INPUT_HANDLE			      (DWORD)(0xfffffff6)
#define STD_OUTPUT_HANDLE			      (DWORD)(0xfffffff5)
#define STD_ERROR_HANDLE			      (DWORD)(0xfffffff4)

#define INVALID_HANDLE_VALUE				     (HANDLE)(-1)

#define GET_TAPE_MEDIA_INFORMATION				       0
#define GET_TAPE_DRIVE_INFORMATION				       1
#define SET_TAPE_MEDIA_INFORMATION				       0
#define SET_TAPE_DRIVE_INFORMATION				       1

#define THREAD_PRIORITY_ABOVE_NORMAL				       1
#define THREAD_PRIORITY_BELOW_NORMAL				     (-1)
#define THREAD_PRIORITY_HIGHEST 				       2
#define THREAD_PRIORITY_IDLE					    (-15)
#define THREAD_PRIORITY_LOWEST					     (-2)
#define THREAD_PRIORITY_NORMAL					       0
#define THREAD_PRIORITY_TIME_CRITICAL				      15
#define THREAD_PRIORITY_ERROR_RETURN			      2147483647

#define TIME_ZONE_ID_UNKNOWN					       0
#define TIME_ZONE_ID_STANDARD					       1
#define TIME_ZONE_ID_DAYLIGHT					       2
#define TIME_ZONE_ID_INVALID				      0xFFFFFFFF

#define FS_CASE_IS_PRESERVED					       2
#define FS_CASE_SENSITIVE					       1
#define FS_UNICODE_STORED_ON_DISK				       4
#define FS_PERSISTENT_ACLS					       8
#define FS_FILE_COMPRESSION					      16
#define FS_VOL_IS_COMPRESSED					   32768

#define GMEM_FIXED						       0
#define GMEM_MOVEABLE						       2
#define GMEM_MODIFY						     128
#define GPTR							      64
#define GHND							      66
#define GMEM_DDESHARE						    8192
#define GMEM_DISCARDABLE					     256
#define GMEM_LOWER						    4096
#define GMEM_NOCOMPACT						      16
#define GMEM_NODISCARD						      32
#define GMEM_NOT_BANKED 					    4096
#define GMEM_NOTIFY						   16384
#define GMEM_SHARE						    8192
#define GMEM_ZEROINIT						      64
#define GMEM_DISCARDED						   16384
#define GMEM_INVALID_HANDLE					   32768
#define GMEM_LOCKCOUNT						     255
#define GMEM_VALID_FLAGS					   32626

#define STATUS_WAIT_0						       0
#define STATUS_ABANDONED_WAIT_0 				    0x80
#define STATUS_USER_APC 					    0xC0
#define STATUS_TIMEOUT						   0x102
#define STATUS_PENDING						   0x103
#define STATUS_SEGMENT_NOTIFICATION			      0x40000005
#define STATUS_GUARD_PAGE_VIOLATION			      0x80000001
#define STATUS_DATATYPE_MISALIGNMENT			      0x80000002
#define STATUS_BREAKPOINT				      0x80000003
#define STATUS_SINGLE_STEP				      0x80000004
#define STATUS_ACCESS_VIOLATION 			      0xC0000005
#define STATUS_IN_PAGE_ERROR				      0xC0000006
#define STATUS_INVALID_HANDLE				      0xC0000008L
#define STATUS_NO_MEMORY				      0xC0000017
#define STATUS_ILLEGAL_INSTRUCTION			      0xC000001D
#define STATUS_NONCONTINUABLE_EXCEPTION 		      0xC0000025
#define STATUS_INVALID_DISPOSITION			      0xC0000026
#define STATUS_ARRAY_BOUNDS_EXCEEDED			      0xC000008C
#define STATUS_FLOAT_DENORMAL_OPERAND			      0xC000008D
#define STATUS_FLOAT_DIVIDE_BY_ZERO			      0xC000008E
#define STATUS_FLOAT_INEXACT_RESULT			      0xC000008F
#define STATUS_FLOAT_INVALID_OPERATION			      0xC0000090
#define STATUS_FLOAT_OVERFLOW				      0xC0000091
#define STATUS_FLOAT_STACK_CHECK			      0xC0000092
#define STATUS_FLOAT_UNDERFLOW				      0xC0000093
#define STATUS_INTEGER_DIVIDE_BY_ZERO			      0xC0000094
#define STATUS_INTEGER_OVERFLOW 			      0xC0000095
#define STATUS_PRIVILEGED_INSTRUCTION			      0xC0000096
#define STATUS_STACK_OVERFLOW				      0xC00000FD
#define STATUS_CONTROL_C_EXIT				      0xC000013A
#define STATUS_DLL_INIT_FAILED				      0xC0000142
#define STATUS_DLL_INIT_FAILED_LOGOFF			      0xC000026B

#define EXCEPTION_ACCESS_VIOLATION		       STATUS_ACCESS_VIOLATION
#define EXCEPTION_DATATYPE_MISALIGNMENT 	     STATUS_DATATYPE_MISALIGNMENT
#define EXCEPTION_BREAKPOINT				  STATUS_BREAKPOINT
#define EXCEPTION_SINGLE_STEP				  STATUS_SINGLE_STEP
#define EXCEPTION_ARRAY_BOUNDS_EXCEEDED 	     STATUS_ARRAY_BOUNDS_EXCEEDED
#define EXCEPTION_FLT_DENORMAL_OPERAND		    STATUS_FLOAT_DENORMAL_OPERAND
#define EXCEPTION_FLT_DIVIDE_BY_ZERO		     STATUS_FLOAT_DIVIDE_BY_ZERO
#define EXCEPTION_FLT_INEXACT_RESULT		     STATUS_FLOAT_INEXACT_RESULT
#define EXCEPTION_FLT_INVALID_OPERATION 	    STATUS_FLOAT_INVALID_OPERATION
#define EXCEPTION_FLT_OVERFLOW				STATUS_FLOAT_OVERFLOW
#define EXCEPTION_FLT_STACK_CHECK		       STATUS_FLOAT_STACK_CHECK
#define EXCEPTION_FLT_UNDERFLOW 			STATUS_FLOAT_UNDERFLOW
#define EXCEPTION_INT_DIVIDE_BY_ZERO		     STATUS_INTEGER_DIVIDE_BY_ZERO
#define EXCEPTION_INT_OVERFLOW			        STATUS_INTEGER_OVERFLOW
#define EXCEPTION_PRIV_INSTRUCTION		     STATUS_PRIVILEGED_INSTRUCTION
#define EXCEPTION_IN_PAGE_ERROR 			 STATUS_IN_PAGE_ERROR
#define EXCEPTION_ILLEGAL_INSTRUCTION		      STATUS_ILLEGAL_INSTRUCTION
#define EXCEPTION_NONCONTINUABLE_EXCEPTION	    STATUS_NONCONTINUABLE_EXCEPTION
#define EXCEPTION_STACK_OVERFLOW		         STATUS_STACK_OVERFLOW
#define EXCEPTION_INVALID_DISPOSITION		      STATUS_INVALID_DISPOSITION
#define EXCEPTION_GUARD_PAGE			      STATUS_GUARD_PAGE_VIOLATION
#define EXCEPTION_INVALID_HANDLE			STATUS_INVALID_HANDLE
#define CONTROL_C_EXIT					STATUS_CONTROL_C_EXIT

#define PROCESS_HEAP_REGION					       1
#define PROCESS_HEAP_UNCOMMITTED_RANGE				       2
#define PROCESS_HEAP_ENTRY_BUSY 				       4
#define PROCESS_HEAP_ENTRY_MOVEABLE				      16
#define PROCESS_HEAP_ENTRY_DDESHARE				      32

#define DONT_RESOLVE_DLL_REFERENCES				       1
#define LOAD_LIBRARY_AS_DATAFILE				       2
#define LOAD_WITH_ALTERED_SEARCH_PATH				       8

#define LMEM_FIXED						       0
#define LMEM_MOVEABLE						       2
#define LMEM_NONZEROLHND					       2
#define LMEM_NONZEROLPTR					       0
#define LMEM_DISCARDABLE					    3840
#define LMEM_NOCOMPACT						      16
#define LMEM_NODISCARD						      32
#define LMEM_ZEROINIT						      64
#define LMEM_DISCARDED						   16384
#define LMEM_MODIFY						     128
#define LMEM_INVALID_HANDLE					   32768
#define LMEM_LOCKCOUNT						     255

#define LPTR							      64
#define LHND							      66
#define NONZEROLHND						       2
#define NONZEROLPTR						       0

#define LOCKFILE_FAIL_IMMEDIATELY				       1
#define LOCKFILE_EXCLUSIVE_LOCK 				       2

#define LOGON32_PROVIDER_DEFAULT				       0
#define LOGON32_PROVIDER_WINNT35				       1
#define LOGON32_LOGON_INTERACTIVE				       2
#define LOGON32_LOGON_NETWORK					       3
#define LOGON32_LOGON_BATCH					       4
#define LOGON32_LOGON_SERVICE					       5
#define LOGON32_LOGON_UNLOCK					       7

#define MOVEFILE_REPLACE_EXISTING				       1
#define MOVEFILE_COPY_ALLOWED					       2
#define MOVEFILE_DELAY_UNTIL_REBOOT				       4
#define MOVEFILE_WRITE_THROUGH					       8

#define MAXIMUM_WAIT_OBJECTS					      64
#define MAXIMUM_SUSPEND_COUNT					    0x7F

#define WAIT_OBJECT_0						       0
#define WAIT_ABANDONED_0					     128

/* WAIT_TIMEOUT is also defined in <winerror.h>.  We MUST ensure that the
 * definitions are IDENTICALLY the same in BOTH headers; they are defined
 * without guards, to give the compiler an opportunity to check this.
 */
#define WAIT_TIMEOUT						     258L

#define WAIT_IO_COMPLETION					    0xC0
#define WAIT_ABANDONED						     128
#define WAIT_FAILED				     ((DWORD)(0xFFFFFFFF))

#define PURGE_TXABORT						       1
#define PURGE_RXABORT						       2
#define PURGE_TXCLEAR						       4
#define PURGE_RXCLEAR						       8

#define EVENTLOG_SUCCESS					       0
#define EVENTLOG_FORWARDS_READ					       4
#define EVENTLOG_BACKWARDS_READ 				       8
#define EVENTLOG_SEEK_READ					       2
#define EVENTLOG_SEQUENTIAL_READ				       1
#define EVENTLOG_ERROR_TYPE					       1
#define EVENTLOG_WARNING_TYPE					       2
#define EVENTLOG_INFORMATION_TYPE				       4
#define EVENTLOG_AUDIT_SUCCESS					       8
#define EVENTLOG_AUDIT_FAILURE					      16

#define FORMAT_MESSAGE_ALLOCATE_BUFFER				     256
#define FORMAT_MESSAGE_IGNORE_INSERTS				     512
#define FORMAT_MESSAGE_FROM_STRING				    1024
#define FORMAT_MESSAGE_FROM_HMODULE				    2048
#define FORMAT_MESSAGE_FROM_SYSTEM				    4096
#define FORMAT_MESSAGE_ARGUMENT_ARRAY				    8192
#define FORMAT_MESSAGE_MAX_WIDTH_MASK				     255

#define EV_BREAK						      64
#define EV_CTS							       8
#define EV_DSR							      16
#define EV_ERR							     128
#define EV_EVENT1						    2048
#define EV_EVENT2						    4096
#define EV_PERR 						     512
#define EV_RING 						     256
#define EV_RLSD 						      32
#define EV_RX80FULL						    1024
#define EV_RXCHAR						       1
#define EV_RXFLAG						       2
#define EV_TXEMPTY						       4

/* also in ddk/ntapi.h */
/* To restore default error mode, call SetErrorMode (0).  */
#define SEM_FAILCRITICALERRORS					  0x0001
#define SEM_NOGPFAULTERRORBOX					  0x0002
#define SEM_NOALIGNMENTFAULTEXCEPT				  0x0004
#define SEM_NOOPENFILEERRORBOX					  0x8000
/* end ntapi.h */

#define SLE_ERROR						       1
#define SLE_MINORERROR						       2
#define SLE_WARNING						       3

#define SHUTDOWN_NORETRY					       1

#define EXCEPTION_EXECUTE_HANDLER				       1
#define EXCEPTION_CONTINUE_EXECUTION				     (-1)
#define EXCEPTION_CONTINUE_SEARCH				       0

#define MAXINTATOM						  0xC000
#define INVALID_ATOM					       ((ATOM)(0))

#define IGNORE							       0
#define INFINITE					      0xFFFFFFFF
#define NOPARITY						       0
#define ODDPARITY						       1
#define EVENPARITY						       2
#define MARKPARITY						       3
#define SPACEPARITY						       4
#define ONESTOPBIT						       0
#define ONE5STOPBITS						       1
#define TWOSTOPBITS						       2
#define CBR_110 						     110
#define CBR_300 						     300
#define CBR_600 						     600
#define CBR_1200						    1200
#define CBR_2400						    2400
#define CBR_4800						    4800
#define CBR_9600						    9600
#define CBR_14400						   14400
#define CBR_19200						   19200
#define CBR_38400						   38400
#define CBR_56000						   56000
#define CBR_57600						   57600
#define CBR_115200						  115200
#define CBR_128000						  128000
#define CBR_256000						  256000

#define BACKUP_INVALID						       0
#define BACKUP_DATA						       1
#define BACKUP_EA_DATA						       2
#define BACKUP_SECURITY_DATA					       3
#define BACKUP_ALTERNATE_DATA					       4
#define BACKUP_LINK						       5
#define BACKUP_PROPERTY_DATA					       6
#define BACKUP_OBJECT_ID					       7
#define BACKUP_REPARSE_DATA					       8
#define BACKUP_SPARSE_BLOCK					       9

#define STREAM_NORMAL_ATTRIBUTE 				       0
#define STREAM_MODIFIED_WHEN_READ				       1
#define STREAM_CONTAINS_SECURITY				       2
#define STREAM_CONTAINS_PROPERTIES				       4

#define STARTF_USESHOWWINDOW					       1
#define STARTF_USESIZE						       2
#define STARTF_USEPOSITION					       4
#define STARTF_USECOUNTCHARS					       8
#define STARTF_USEFILLATTRIBUTE 				      16
#define STARTF_RUNFULLSCREEN					      32
#define STARTF_FORCEONFEEDBACK					      64
#define STARTF_FORCEOFFFEEDBACK 				     128
#define STARTF_USESTDHANDLES					     256
#define STARTF_USEHOTKEY					     512

#define TC_NORMAL						       0
#define TC_HARDERR						       1
#define TC_GP_TRAP						       2
#define TC_SIGNAL						       3

#define AC_LINE_OFFLINE 					       0
#define AC_LINE_ONLINE						       1
#define AC_LINE_BACKUP_POWER					       2
#define AC_LINE_UNKNOWN 					     255

#define BATTERY_FLAG_HIGH					       1
#define BATTERY_FLAG_LOW					       2
#define BATTERY_FLAG_CRITICAL					       4
#define BATTERY_FLAG_CHARGING					       8
#define BATTERY_FLAG_NO_BATTERY 				     128
#define BATTERY_FLAG_UNKNOWN					     255
#define BATTERY_PERCENTAGE_UNKNOWN				     255
#define BATTERY_LIFE_UNKNOWN				      0xFFFFFFFF

#define DDD_RAW_TARGET_PATH					       1
#define DDD_REMOVE_DEFINITION					       2
#define DDD_EXACT_MATCH_ON_REMOVE				       4

#define HINSTANCE_ERROR 					      32

#define MS_CTS_ON						      16
#define MS_DSR_ON						      32
#define MS_RING_ON						      64
#define MS_RLSD_ON						     128

#define DTR_CONTROL_DISABLE					       0
#define DTR_CONTROL_ENABLE					       1
#define DTR_CONTROL_HANDSHAKE					       2

#define RTS_CONTROL_DISABLE					       0
#define RTS_CONTROL_ENABLE					       1
#define RTS_CONTROL_HANDSHAKE					       2
#define RTS_CONTROL_TOGGLE					       3

#define SECURITY_ANONYMOUS			      (SecurityAnonymous<<16)
#define SECURITY_IDENTIFICATION 		      (SecurityIdentification<<16)
#define SECURITY_IMPERSONATION			      (SecurityImpersonation<<16)
#define SECURITY_DELEGATION			      (SecurityDelegation<<16)
#define SECURITY_CONTEXT_TRACKING				 0x40000
#define SECURITY_EFFECTIVE_ONLY 				 0x80000
#define SECURITY_SQOS_PRESENT					0x100000
#define SECURITY_VALID_SQOS_FLAGS				0x1F0000

#define INVALID_FILE_SIZE				      0xFFFFFFFF
#define TLS_OUT_OF_INDEXES			      (DWORD)(0xFFFFFFFF)

#define GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS		      0x00000004
#define GET_MODULE_HANDLE_EX_FLAG_PIN			      0x00000001
#define GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT	      0x00000002

#define WRITE_WATCH_FLAG_RESET					       1

#if _WIN32_WINNT >= _WIN32_WINNT_NT4
/* Constants associated with features supported only on WinNT,
 * from NT4 onwards.
 */
#define LOGON32_PROVIDER_WINNT40				       2

#if (_WIN32_WINNT > 0x0500)
/* FIXME: What does this mean?  0x0500 is Win2K, so greater than Win2K
 * implies WinXP and later, so does it mean >= WinXP, or is it a typo
 * for >= Win2K?  Should use >= comparator for clarity.
 */
#define COPY_FILE_ALLOW_DECRYPTED_DESTINATION			  0x0008
#endif

#if _WIN32_WINNT >= _WIN32_WINNT_WIN2K
/* Constants associated with features supported only on WinXP and later.
 */
#define FILE_FLAG_FIRST_PIPE_INSTANCE				  524288

#define LOGON32_PROVIDER_WINNT50				       3
#define LOGON32_LOGON_NETWORK_CLEARTEXT 			       8
#define LOGON32_LOGON_NEW_CREDENTIALS				       9

#define REPLACEFILE_WRITE_THROUGH			      0x00000001
#define REPLACEFILE_IGNORE_MERGE_ERRORS 		      0x00000002

#if (_WIN32_WINNT > 0x0501)
/* FIXME: Once again, what does this mean?  Should use >= comparator, for
 * clarity.  0x0501 is WinXP, but does > WinXP mean Server-2003 (0x0502)?
 * Or deoes it mean Vista (0x0600)?  (Intuitively, since symlinks weren't
 * supported prior to Vista, the latter seems likely).
 */
#define COPY_FILE_COPY_SYMLINK					  0x0800
#define COPY_FILE_NO_BUFFERING					  0x1000
#endif

#if _WIN32_WINNT >= _WIN32_WINNT_WINXP
/* Constants associated with features supported only on WinXP and later.
 */
#define ACTCTX_FLAG_PROCESSOR_ARCHITECTURE_VALID	      0x00000001
#define ACTCTX_FLAG_LANGID_VALID			      0x00000002
#define ACTCTX_FLAG_ASSEMBLY_DIRECTORY_VALID		      0x00000004
#define ACTCTX_FLAG_RESOURCE_NAME_VALID 		      0x00000008
#define ACTCTX_FLAG_SET_PROCESS_DEFAULT 		      0x00000010
#define ACTCTX_FLAG_APPLICATION_NAME_VALID		      0x00000020
#define ACTCTX_FLAG_HMODULE_VALID			      0x00000080
#define DEACTIVATE_ACTCTX_FLAG_FORCE_EARLY_DEACTIVATION       0x00000001
#define FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX		      0x00000001
#define QUERY_ACTCTX_FLAG_USE_ACTIVE_ACTCTX		      0x00000004
#define QUERY_ACTCTX_FLAG_ACTCTX_IS_HMODULE		      0x00000008
#define QUERY_ACTCTX_FLAG_ACTCTX_IS_ADDRESS		      0x00000010

#if _WIN32_WINNT >= _WIN32_WINNT_VISTA
/* Constants associated with features supported only on Vista and later.
 */
#define THREAD_MODE_BACKGROUND_BEGIN			      0x00010000
#define THREAD_MODE_BACKGROUND_END			      0x00020000

/* http://msdn.microsoft.com/en-us/library/aa363866%28VS.85%29.aspx */
#define SYMBOLIC_LINK_FLAG_DIRECTORY				     0x1

/* http://msdn.microsoft.com/en-us/library/aa364962%28VS.85%29.aspx */
#define FILE_NAME_NORMALIZED					     0x0
#define FILE_NAME_OPENED					     0x8

#define VOLUME_NAME_DOS 					     0x0
#define VOLUME_NAME_GUID					     0x1
#define VOLUME_NAME_NONE					     0x4
#define VOLUME_NAME_NT						     0x2

#if _WIN32_WINNT >= _WIN32_WINNT_WIN7
/* Constants associated with features supported only on Win7 and later.
 */
#define PROCESS_DEP_ENABLE					       1
#define PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION 		       2

#endif	/* Win7 and later */
#endif	/* WinVista and later */
#endif	/* WinXP and later */
#endif	/* Win2K and later */
#endif	/* WinNT from NT4 */

#ifndef RC_INVOKED

typedef struct _FILETIME
{ DWORD 			dwLowDateTime;
  DWORD 			dwHighDateTime;
} FILETIME, *PFILETIME, *LPFILETIME;

typedef struct _BY_HANDLE_FILE_INFORMATION
{ DWORD 			dwFileAttributes;
  FILETIME			ftCreationTime;
  FILETIME			ftLastAccessTime;
  FILETIME			ftLastWriteTime;
  DWORD 			dwVolumeSerialNumber;
  DWORD 			nFileSizeHigh;
  DWORD 			nFileSizeLow;
  DWORD 			nNumberOfLinks;
  DWORD 			nFileIndexHigh;
  DWORD 			nFileIndexLow;
} BY_HANDLE_FILE_INFORMATION, *LPBY_HANDLE_FILE_INFORMATION;

typedef struct _DCB
{ DWORD 			DCBlength;
  DWORD 			BaudRate;
  DWORD 			fBinary:1;
  DWORD 			fParity:1;
  DWORD 			fOutxCtsFlow:1;
  DWORD 			fOutxDsrFlow:1;
  DWORD 			fDtrControl:2;
  DWORD 			fDsrSensitivity:1;
  DWORD 			fTXContinueOnXoff:1;
  DWORD 			fOutX:1;
  DWORD 			fInX:1;
  DWORD 			fErrorChar:1;
  DWORD 			fNull:1;
  DWORD 			fRtsControl:2;
  DWORD 			fAbortOnError:1;
  DWORD 			fDummy2:17;
  WORD				wReserved;
  WORD				XonLim;
  WORD				XoffLim;
  BYTE				ByteSize;
  BYTE				Parity;
  BYTE				StopBits;
  char				XonChar;
  char				XoffChar;
  char				ErrorChar;
  char				EofChar;
  char				EvtChar;
  WORD				wReserved1;
} DCB, *LPDCB;

typedef struct _COMM_CONFIG
{ DWORD 			dwSize;
  WORD				wVersion;
  WORD				wReserved;
  DCB				dcb;
  DWORD 			dwProviderSubType;
  DWORD 			dwProviderOffset;
  DWORD 			dwProviderSize;
  WCHAR 			wcProviderData[1];
} COMMCONFIG, *LPCOMMCONFIG;

typedef struct _COMMPROP
{ WORD				wPacketLength;
  WORD				wPacketVersion;
  DWORD 			dwServiceMask;
  DWORD 			dwReserved1;
  DWORD 			dwMaxTxQueue;
  DWORD 			dwMaxRxQueue;
  DWORD 			dwMaxBaud;
  DWORD 			dwProvSubType;
  DWORD 			dwProvCapabilities;
  DWORD 			dwSettableParams;
  DWORD 			dwSettableBaud;
  WORD				wSettableData;
  WORD				wSettableStopParity;
  DWORD 			dwCurrentTxQueue;
  DWORD 			dwCurrentRxQueue;
  DWORD 			dwProvSpec1;
  DWORD 			dwProvSpec2;
  WCHAR 			wcProvChar[1];
} COMMPROP, *LPCOMMPROP;

typedef struct _COMMTIMEOUTS
{ DWORD 			ReadIntervalTimeout;
  DWORD 			ReadTotalTimeoutMultiplier;
  DWORD 			ReadTotalTimeoutConstant;
  DWORD 			WriteTotalTimeoutMultiplier;
  DWORD 			WriteTotalTimeoutConstant;
} COMMTIMEOUTS, *LPCOMMTIMEOUTS;

typedef struct _COMSTAT
{ DWORD 			fCtsHold:1;
  DWORD 			fDsrHold:1;
  DWORD 			fRlsdHold:1;
  DWORD 			fXoffHold:1;
  DWORD 			fXoffSent:1;
  DWORD 			fEof:1;
  DWORD 			fTxim:1;
  DWORD 			fReserved:25;
  DWORD 			cbInQue;
  DWORD 			cbOutQue;
} COMSTAT, *LPCOMSTAT;

typedef DWORD (WINAPI *LPTHREAD_START_ROUTINE)(LPVOID);

typedef struct _CREATE_PROCESS_DEBUG_INFO
{ HANDLE			hFile;
  HANDLE			hProcess;
  HANDLE			hThread;
  LPVOID			lpBaseOfImage;
  DWORD 			dwDebugInfoFileOffset;
  DWORD 			nDebugInfoSize;
  LPVOID			lpThreadLocalBase;
  LPTHREAD_START_ROUTINE	lpStartAddress;
  LPVOID			lpImageName;
  WORD				fUnicode;
} CREATE_PROCESS_DEBUG_INFO, *LPCREATE_PROCESS_DEBUG_INFO;

typedef struct _CREATE_THREAD_DEBUG_INFO
{ HANDLE			hThread;
  LPVOID			lpThreadLocalBase;
  LPTHREAD_START_ROUTINE	lpStartAddress;
} CREATE_THREAD_DEBUG_INFO, *LPCREATE_THREAD_DEBUG_INFO;

typedef struct _EXCEPTION_DEBUG_INFO
{ EXCEPTION_RECORD		ExceptionRecord;
  DWORD 			dwFirstChance;
} EXCEPTION_DEBUG_INFO, *LPEXCEPTION_DEBUG_INFO;

typedef struct _EXIT_THREAD_DEBUG_INFO
{ DWORD 			dwExitCode;
} EXIT_THREAD_DEBUG_INFO, *LPEXIT_THREAD_DEBUG_INFO;

typedef struct _EXIT_PROCESS_DEBUG_INFO
{ DWORD 			dwExitCode;
} EXIT_PROCESS_DEBUG_INFO, *LPEXIT_PROCESS_DEBUG_INFO;

typedef struct _LOAD_DLL_DEBUG_INFO
{ HANDLE			hFile;
  LPVOID			lpBaseOfDll;
  DWORD 			dwDebugInfoFileOffset;
  DWORD 			nDebugInfoSize;
  LPVOID			lpImageName;
  WORD				fUnicode;
} LOAD_DLL_DEBUG_INFO, *LPLOAD_DLL_DEBUG_INFO;

typedef struct _UNLOAD_DLL_DEBUG_INFO
{ LPVOID			lpBaseOfDll;
} UNLOAD_DLL_DEBUG_INFO, *LPUNLOAD_DLL_DEBUG_INFO;

typedef struct _OUTPUT_DEBUG_STRING_INFO
{ LPSTR 			lpDebugStringData;
  WORD				fUnicode;
  WORD				nDebugStringLength;
} OUTPUT_DEBUG_STRING_INFO, *LPOUTPUT_DEBUG_STRING_INFO;

typedef struct _RIP_INFO
{ DWORD 			dwError;
  DWORD 			dwType;
} RIP_INFO, *LPRIP_INFO;

typedef struct _DEBUG_EVENT
{ DWORD 			dwDebugEventCode;
  DWORD 			dwProcessId;
  DWORD 			dwThreadId;
  union
  { EXCEPTION_DEBUG_INFO	  Exception;
    CREATE_THREAD_DEBUG_INFO	  CreateThread;
    CREATE_PROCESS_DEBUG_INFO	  CreateProcessInfo;
    EXIT_THREAD_DEBUG_INFO	  ExitThread;
    EXIT_PROCESS_DEBUG_INFO	  ExitProcess;
    LOAD_DLL_DEBUG_INFO 	  LoadDll;
    UNLOAD_DLL_DEBUG_INFO	  UnloadDll;
    OUTPUT_DEBUG_STRING_INFO	  DebugString;
    RIP_INFO			  RipInfo;
  }				u;
} DEBUG_EVENT, *LPDEBUG_EVENT;

typedef struct _OVERLAPPED
{ ULONG_PTR			Internal;
  ULONG_PTR			InternalHigh;
  __GNUC_EXTENSION union
  { __GNUC_EXTENSION struct
    { DWORD			    Offset;
      DWORD			    OffsetHigh;
    };
    PVOID			  Pointer;
  };
  HANDLE			hEvent;
} OVERLAPPED, *POVERLAPPED, *LPOVERLAPPED;

typedef struct _STARTUPINFOA
{ DWORD 			cb;
  LPSTR 			lpReserved;
  LPSTR 			lpDesktop;
  LPSTR 			lpTitle;
  DWORD 			dwX;
  DWORD 			dwY;
  DWORD 			dwXSize;
  DWORD 			dwYSize;
  DWORD 			dwXCountChars;
  DWORD 			dwYCountChars;
  DWORD 			dwFillAttribute;
  DWORD 			dwFlags;
  WORD				wShowWindow;
  WORD				cbReserved2;
  PBYTE 			lpReserved2;
  HANDLE			hStdInput;
  HANDLE			hStdOutput;
  HANDLE			hStdError;
} STARTUPINFOA, *LPSTARTUPINFOA;

typedef struct _STARTUPINFOW
{ DWORD 			cb;
  LPWSTR			lpReserved;
  LPWSTR			lpDesktop;
  LPWSTR			lpTitle;
  DWORD 			dwX;
  DWORD 			dwY;
  DWORD 			dwXSize;
  DWORD 			dwYSize;
  DWORD 			dwXCountChars;
  DWORD 			dwYCountChars;
  DWORD 			dwFillAttribute;
  DWORD 			dwFlags;
  WORD				wShowWindow;
  WORD				cbReserved2;
  PBYTE 			lpReserved2;
  HANDLE			hStdInput;
  HANDLE			hStdOutput;
  HANDLE			hStdError;
} STARTUPINFOW, *LPSTARTUPINFOW;

typedef __AW_ALIAS__(STARTUPINFO), *LPSTARTUPINFO;

typedef struct _PROCESS_INFORMATION
{ HANDLE			hProcess;
  HANDLE			hThread;
  DWORD 			dwProcessId;
  DWORD 			dwThreadId;
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;

typedef struct _CRITICAL_SECTION_DEBUG
{ WORD				Type;
  WORD				CreatorBackTraceIndex;
  struct _CRITICAL_SECTION *CriticalSection;
  LIST_ENTRY			ProcessLocksList;
  DWORD 			EntryCount;
  DWORD 			ContentionCount;
  DWORD 			Spare[2];
} CRITICAL_SECTION_DEBUG, *PCRITICAL_SECTION_DEBUG;

typedef struct _CRITICAL_SECTION
{ PCRITICAL_SECTION_DEBUG	DebugInfo;
  LONG				LockCount;
  LONG				RecursionCount;
  HANDLE			OwningThread;
  HANDLE			LockSemaphore;
  DWORD 			SpinCount;
} CRITICAL_SECTION, *PCRITICAL_SECTION, *LPCRITICAL_SECTION;

typedef struct _SYSTEMTIME
{ WORD				wYear;
  WORD				wMonth;
  WORD				wDayOfWeek;
  WORD				wDay;
  WORD				wHour;
  WORD				wMinute;
  WORD				wSecond;
  WORD				wMilliseconds;
} SYSTEMTIME, *LPSYSTEMTIME;

typedef struct _WIN32_FILE_ATTRIBUTE_DATA
{ DWORD 			dwFileAttributes;
  FILETIME			ftCreationTime;
  FILETIME			ftLastAccessTime;
  FILETIME			ftLastWriteTime;
  DWORD 			nFileSizeHigh;
  DWORD 			nFileSizeLow;
} WIN32_FILE_ATTRIBUTE_DATA, *LPWIN32_FILE_ATTRIBUTE_DATA;

typedef struct _WIN32_FIND_DATAA
{ DWORD 			dwFileAttributes;
  FILETIME			ftCreationTime;
  FILETIME			ftLastAccessTime;
  FILETIME			ftLastWriteTime;
  DWORD 			nFileSizeHigh;
  DWORD 			nFileSizeLow;
# ifdef _WIN32_WCE
  DWORD 			dwOID;
# else
  DWORD 			dwReserved0;
  DWORD 			dwReserved1;
# endif
  CHAR				cFileName[MAX_PATH];
# ifndef _WIN32_WCE
  CHAR				cAlternateFileName[14];
# endif
} WIN32_FIND_DATAA, *PWIN32_FIND_DATAA, *LPWIN32_FIND_DATAA;

typedef struct _WIN32_FIND_DATAW
{ DWORD 			dwFileAttributes;
  FILETIME			ftCreationTime;
  FILETIME			ftLastAccessTime;
  FILETIME			ftLastWriteTime;
  DWORD 			nFileSizeHigh;
  DWORD 			nFileSizeLow;
# ifdef _WIN32_WCE
  DWORD 			dwOID;
# else
  DWORD 			dwReserved0;
  DWORD 			dwReserved1;
# endif
  WCHAR 			cFileName[MAX_PATH];
# ifndef _WIN32_WCE
  WCHAR 			cAlternateFileName[14];
# endif
} WIN32_FIND_DATAW, *PWIN32_FIND_DATAW, *LPWIN32_FIND_DATAW;

typedef __AW_ALIAS__(WIN32_FIND_DATA), *PWIN32_FIND_DATA, *LPWIN32_FIND_DATA;

typedef struct _WIN32_STREAM_ID
{ DWORD 			dwStreamId;
  DWORD 			dwStreamAttributes;
  LARGE_INTEGER 		Size;
  DWORD 			dwStreamNameSize;
  WCHAR 			cStreamName[ANYSIZE_ARRAY];
} WIN32_STREAM_ID, *LPWIN32_STREAM_ID;

typedef enum _FINDEX_INFO_LEVELS
{ FindExInfoStandard,
  FindExInfoMaxInfoLevel
} FINDEX_INFO_LEVELS;

typedef enum _FINDEX_SEARCH_OPS
{ FindExSearchNameMatch,
  FindExSearchLimitToDirectories,
  FindExSearchLimitToDevices,
  FindExSearchMaxSearchOp
} FINDEX_SEARCH_OPS;

typedef enum _ACL_INFORMATION_CLASS
{ AclRevisionInformation=1,
  AclSizeInformation
} ACL_INFORMATION_CLASS;

typedef struct tagHW_PROFILE_INFOA
{ DWORD 			dwDockInfo;
  CHAR				szHwProfileGuid[HW_PROFILE_GUIDLEN];
  CHAR				szHwProfileName[MAX_PROFILE_LEN];
} HW_PROFILE_INFOA, *LPHW_PROFILE_INFOA;

typedef struct tagHW_PROFILE_INFOW
{ DWORD 			dwDockInfo;
  WCHAR 			szHwProfileGuid[HW_PROFILE_GUIDLEN];
  WCHAR 			szHwProfileName[MAX_PROFILE_LEN];
} HW_PROFILE_INFOW, *LPHW_PROFILE_INFOW;

typedef __AW_ALIAS__(HW_PROFILE_INFO), *LPHW_PROFILE_INFO;

typedef enum _GET_FILEEX_INFO_LEVELS
{ GetFileExInfoStandard,
  GetFileExMaxInfoLevel
} GET_FILEEX_INFO_LEVELS;

typedef struct _SYSTEM_INFO
{ _ANONYMOUS_UNION union
  { DWORD			  dwOemId;
    _ANONYMOUS_STRUCT struct
    { WORD			    wProcessorArchitecture;
      WORD			    wReserved;
    }				  DUMMYSTRUCTNAME;
  }				DUMMYUNIONNAME;
  DWORD 			dwPageSize;
  PVOID 			lpMinimumApplicationAddress;
  PVOID 			lpMaximumApplicationAddress;
  DWORD 			dwActiveProcessorMask;
  DWORD 			dwNumberOfProcessors;
  DWORD 			dwProcessorType;
  DWORD 			dwAllocationGranularity;
  WORD				wProcessorLevel;
  WORD				wProcessorRevision;
} SYSTEM_INFO, *LPSYSTEM_INFO;

typedef struct _SYSTEM_POWER_STATUS
{ BYTE				ACLineStatus;
  BYTE				BatteryFlag;
  BYTE				BatteryLifePercent;
  BYTE				Reserved1;
  DWORD 			BatteryLifeTime;
  DWORD 			BatteryFullLifeTime;
} SYSTEM_POWER_STATUS, *LPSYSTEM_POWER_STATUS;

typedef struct _TIME_ZONE_INFORMATION
{ LONG				Bias;
  WCHAR 			StandardName[32];
  SYSTEMTIME			StandardDate;
  LONG				StandardBias;
  WCHAR 			DaylightName[32];
  SYSTEMTIME			DaylightDate;
  LONG				DaylightBias;
} TIME_ZONE_INFORMATION, *LPTIME_ZONE_INFORMATION;

typedef struct _MEMORYSTATUS
{ DWORD 			dwLength;
  DWORD 			dwMemoryLoad;
  DWORD 			dwTotalPhys;
  DWORD 			dwAvailPhys;
  DWORD 			dwTotalPageFile;
  DWORD 			dwAvailPageFile;
  DWORD 			dwTotalVirtual;
  DWORD 			dwAvailVirtual;
} MEMORYSTATUS, *LPMEMORYSTATUS;

typedef struct _LDT_ENTRY
{ WORD				LimitLow;
  WORD				BaseLow;
  union
  { struct
    { BYTE			    BaseMid;
      BYTE			    Flags1;
      BYTE			    Flags2;
      BYTE			    BaseHi;
    }				  Bytes;
    struct
    { DWORD			    BaseMid:8;
      DWORD			    Type:5;
      DWORD			    Dpl:2;
      DWORD			    Pres:1;
      DWORD			    LimitHi:4;
      DWORD			    Sys:1;
      DWORD			    Reserved_0:1;
      DWORD			    Default_Big:1;
      DWORD			    Granularity:1;
      DWORD			    BaseHi:8;
    }				  Bits;
  }				HighWord;
} LDT_ENTRY, *PLDT_ENTRY, *LPLDT_ENTRY;

typedef struct _PROCESS_HEAP_ENTRY
{ PVOID 			lpData;
  DWORD 			cbData;
  BYTE cbOverhead;
  BYTE iRegionIndex;
  WORD wFlags;
  _ANONYMOUS_UNION union
  { struct
    { HANDLE hMem;
      DWORD dwReserved[3];
    } Block;
    struct
    { DWORD dwCommittedSize;
      DWORD dwUnCommittedSize;
      LPVOID lpFirstBlock;
      LPVOID lpLastBlock;
    } Region;
  } DUMMYUNIONNAME;
} PROCESS_HEAP_ENTRY, *LPPROCESS_HEAP_ENTRY;

typedef struct _OFSTRUCT
{ BYTE cBytes;
  BYTE fFixedDisk;
  WORD nErrCode;
  WORD Reserved1;
  WORD Reserved2;
  CHAR szPathName[OFS_MAXPATHNAME];
} OFSTRUCT, *LPOFSTRUCT, *POFSTRUCT;

typedef struct _WIN_CERTIFICATE
{ DWORD 			dwLength;
  WORD wRevision;
  WORD wCertificateType;
  BYTE bCertificate[1];
} WIN_CERTIFICATE, *LPWIN_CERTIFICATE;

typedef DWORD (WINAPI *LPPROGRESS_ROUTINE)
( LARGE_INTEGER, LARGE_INTEGER, LARGE_INTEGER, LARGE_INTEGER,
  DWORD, DWORD, HANDLE, HANDLE, LPVOID
);
typedef void (WINAPI *LPFIBER_START_ROUTINE)(PVOID);

#define ENUMRESLANGPROC __AW_SUFFIXED__(ENUMRESLANGPROC)
typedef BOOL (CALLBACK *ENUMRESLANGPROCA)(HMODULE, LPCSTR, LPCSTR, WORD, LONG);
typedef BOOL (CALLBACK *ENUMRESLANGPROCW)
(HMODULE, LPCWSTR, LPCWSTR, WORD, LONG);

#define ENUMRESNAMEPROC __AW_SUFFIXED__(ENUMRESNAMEPROC)
typedef BOOL (CALLBACK *ENUMRESNAMEPROCA)(HMODULE, LPCSTR, LPSTR, LONG);
typedef BOOL (CALLBACK *ENUMRESNAMEPROCW)(HMODULE, LPCWSTR, LPWSTR, LONG);

#define ENUMRESTYPEPROC __AW_SUFFIXED__(ENUMRESTYPEPROC)
typedef BOOL (CALLBACK *ENUMRESTYPEPROCA)(HMODULE, LPSTR, LONG);
typedef BOOL (CALLBACK *ENUMRESTYPEPROCW)(HMODULE, LPWSTR, LONG);

typedef void (CALLBACK *LPOVERLAPPED_COMPLETION_ROUTINE)
(DWORD, DWORD, LPOVERLAPPED);
typedef LONG (CALLBACK *PTOP_LEVEL_EXCEPTION_FILTER)(LPEXCEPTION_POINTERS);
typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;
typedef void (APIENTRY *PAPCFUNC)(ULONG_PTR);
typedef void (CALLBACK *PTIMERAPCROUTINE)(PVOID, DWORD, DWORD);

#define MAKEINTATOM(i)  (LPTSTR)((DWORD)((WORD)(i)))

/* Functions */
#ifndef UNDER_CE
int APIENTRY WinMain (HINSTANCE, HINSTANCE, LPSTR, int);
#else
int APIENTRY WinMain (HINSTANCE, HINSTANCE, LPWSTR, int);
#endif

int APIENTRY wWinMain (HINSTANCE, HINSTANCE, LPWSTR, int);

WINBASEAPI long WINAPI _hread (HFILE, LPVOID, long);
WINBASEAPI long WINAPI _hwrite (HFILE, LPCSTR, long);
WINBASEAPI HFILE WINAPI _lclose (HFILE);
WINBASEAPI HFILE WINAPI _lcreat (LPCSTR, int);
WINBASEAPI LONG WINAPI _llseek (HFILE, LONG, int);
WINBASEAPI HFILE WINAPI _lopen (LPCSTR, int);
WINBASEAPI UINT WINAPI _lread (HFILE, LPVOID, UINT);
WINBASEAPI UINT WINAPI _lwrite (HFILE, LPCSTR, UINT);

#define AbnormalTermination()  FALSE

WINBASEAPI BOOL WINAPI AccessCheck
( PSECURITY_DESCRIPTOR, HANDLE, DWORD, PGENERIC_MAPPING, PPRIVILEGE_SET,
  PDWORD, PDWORD, PBOOL
);

#define AccessCheckAndAuditAlarm __AW_SUFFIXED__(AccessCheckAndAuditAlarm)
WINBASEAPI BOOL WINAPI AccessCheckAndAuditAlarmA
( LPCSTR, LPVOID, LPSTR, LPSTR, PSECURITY_DESCRIPTOR, DWORD, PGENERIC_MAPPING,
  BOOL, PDWORD, PBOOL, PBOOL
);
WINBASEAPI BOOL WINAPI AccessCheckAndAuditAlarmW
( LPCWSTR, LPVOID, LPWSTR, LPWSTR, PSECURITY_DESCRIPTOR, DWORD,
  PGENERIC_MAPPING, BOOL, PDWORD, PBOOL, PBOOL
);

WINBASEAPI BOOL WINAPI AddAccessAllowedAce (PACL, DWORD, DWORD, PSID);
WINBASEAPI BOOL WINAPI AddAccessDeniedAce (PACL, DWORD, DWORD, PSID);
WINBASEAPI BOOL WINAPI AddAce (PACL, DWORD, DWORD, PVOID, DWORD);

#define AddAtom __AW_SUFFIXED__(AddAtom)
WINBASEAPI ATOM WINAPI AddAtomA (LPCSTR);
WINBASEAPI ATOM WINAPI AddAtomW (LPCWSTR);

WINBASEAPI BOOL WINAPI AddAuditAccessAce (PACL, DWORD, DWORD, PSID, BOOL, BOOL);
WINBASEAPI BOOL WINAPI AdjustTokenGroups
(HANDLE, BOOL, PTOKEN_GROUPS, DWORD, PTOKEN_GROUPS, PDWORD);
WINBASEAPI BOOL WINAPI AdjustTokenPrivileges
(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
WINBASEAPI BOOL WINAPI AllocateAndInitializeSid
( PSID_IDENTIFIER_AUTHORITY, BYTE, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD,
  DWORD, DWORD, PSID *
);
WINBASEAPI BOOL WINAPI AllocateLocallyUniqueId (PLUID);
WINBASEAPI BOOL WINAPI AreAllAccessesGranted (DWORD, DWORD);
WINBASEAPI BOOL WINAPI AreAnyAccessesGranted (DWORD, DWORD);
WINBASEAPI BOOL WINAPI AreFileApisANSI (void);

#define BackupEventLog __AW_SUFFIXED__(BackupEventLog)
WINBASEAPI BOOL WINAPI BackupEventLogA (HANDLE, LPCSTR);
WINBASEAPI BOOL WINAPI BackupEventLogW (HANDLE, LPCWSTR);

WINBASEAPI BOOL WINAPI BackupRead
(HANDLE, LPBYTE, DWORD, LPDWORD, BOOL, BOOL, LPVOID *);
WINBASEAPI BOOL WINAPI BackupSeek
(HANDLE, DWORD, DWORD, LPDWORD, LPDWORD, LPVOID *);
WINBASEAPI BOOL WINAPI BackupWrite
(HANDLE, LPBYTE, DWORD, LPDWORD, BOOL, BOOL, LPVOID *);
WINBASEAPI BOOL WINAPI Beep (DWORD, DWORD);

#define BeginUpdateResource __AW_SUFFIXED__(BeginUpdateResource)
WINBASEAPI HANDLE WINAPI BeginUpdateResourceA (LPCSTR, BOOL);
WINBASEAPI HANDLE WINAPI BeginUpdateResourceW (LPCWSTR, BOOL);

#define BuildCommDCB __AW_SUFFIXED__(BuildCommDCB)
WINBASEAPI BOOL WINAPI BuildCommDCBA (LPCSTR, LPDCB);
WINBASEAPI BOOL WINAPI BuildCommDCBW (LPCWSTR, LPDCB);

#define BuildCommDCBAndTimeouts __AW_SUFFIXED__(BuildCommDCBAndTimeouts)
WINBASEAPI BOOL WINAPI BuildCommDCBAndTimeoutsA (LPCSTR, LPDCB, LPCOMMTIMEOUTS);
WINBASEAPI BOOL WINAPI BuildCommDCBAndTimeoutsW
(LPCWSTR, LPDCB, LPCOMMTIMEOUTS);

#define CallNamedPipe __AW_SUFFIXED__(CallNamedPipe)
WINBASEAPI BOOL WINAPI CallNamedPipeA
(LPCSTR, PVOID, DWORD, PVOID, DWORD, PDWORD, DWORD);
WINBASEAPI BOOL WINAPI CallNamedPipeW
(LPCWSTR, PVOID, DWORD, PVOID, DWORD, PDWORD, DWORD);

WINBASEAPI BOOL WINAPI CancelDeviceWakeupRequest (HANDLE);
WINBASEAPI BOOL WINAPI CancelIo (HANDLE);
WINBASEAPI BOOL WINAPI CancelWaitableTimer (HANDLE);
WINBASEAPI BOOL WINAPI ClearCommBreak (HANDLE);
WINBASEAPI BOOL WINAPI ClearCommError (HANDLE, PDWORD, LPCOMSTAT);

#define ClearEventLog __AW_SUFFIXED__(ClearEventLog)
WINBASEAPI BOOL WINAPI ClearEventLogA (HANDLE, LPCSTR);
WINBASEAPI BOOL WINAPI ClearEventLogW (HANDLE, LPCWSTR);

WINBASEAPI BOOL WINAPI CloseEventLog (HANDLE);
WINBASEAPI BOOL WINAPI CloseHandle (HANDLE);

#define CommConfigDialog __AW_SUFFIXED__(CommConfigDialog)
WINBASEAPI BOOL WINAPI CommConfigDialogA (LPCSTR, HWND, LPCOMMCONFIG);
WINBASEAPI BOOL WINAPI CommConfigDialogW (LPCWSTR, HWND, LPCOMMCONFIG);

WINBASEAPI LONG WINAPI CompareFileTime (CONST FILETIME *, CONST FILETIME *);
WINBASEAPI BOOL WINAPI ConnectNamedPipe (HANDLE, LPOVERLAPPED);
WINBASEAPI BOOL WINAPI ContinueDebugEvent (DWORD, DWORD, DWORD);
WINBASEAPI PVOID WINAPI ConvertThreadToFiber (PVOID);

#define CopyFile __AW_SUFFIXED__(CopyFile)
WINBASEAPI BOOL WINAPI CopyFileA (LPCSTR, LPCSTR, BOOL);
WINBASEAPI BOOL WINAPI CopyFileW (LPCWSTR, LPCWSTR, BOOL);

#define CopyFileEx __AW_SUFFIXED__(CopyFileEx)
WINBASEAPI BOOL WINAPI CopyFileExA
(LPCSTR, LPCSTR, LPPROGRESS_ROUTINE, LPVOID, LPBOOL, DWORD);
WINBASEAPI BOOL WINAPI CopyFileExW
(LPCWSTR, LPCWSTR, LPPROGRESS_ROUTINE, LPVOID, LPBOOL, DWORD);

#define RtlMoveMemory	      memmove
#define RtlCopyMemory	      memcpy
#define RtlFillMemory(d,l,f)  memset((d),(f),(l))
#define RtlZeroMemory(d,l)    RtlFillMemory((d),(l),0)
#define MoveMemory	      RtlMoveMemory
#define CopyMemory	      RtlCopyMemory
#define FillMemory	      RtlFillMemory
#define ZeroMemory	      RtlZeroMemory

WINBASEAPI BOOL WINAPI CopySid (DWORD, PSID, PSID);

#define CreateDirectory __AW_SUFFIXED__(CreateDirectory)
WINBASEAPI BOOL WINAPI CreateDirectoryA (LPCSTR, LPSECURITY_ATTRIBUTES);
WINBASEAPI BOOL WINAPI CreateDirectoryW (LPCWSTR, LPSECURITY_ATTRIBUTES);

#define CreateDirectoryEx __AW_SUFFIXED__(CreateDirectoryEx)
WINBASEAPI BOOL WINAPI CreateDirectoryExA
(LPCSTR, LPCSTR, LPSECURITY_ATTRIBUTES);
WINBASEAPI BOOL WINAPI CreateDirectoryExW
(LPCWSTR, LPCWSTR, LPSECURITY_ATTRIBUTES);

#define CreateEvent __AW_SUFFIXED__(CreateEvent)
WINBASEAPI HANDLE WINAPI CreateEventA
(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
WINBASEAPI HANDLE WINAPI CreateEventW
(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);

WINBASEAPI LPVOID WINAPI CreateFiber (SIZE_T, LPFIBER_START_ROUTINE, LPVOID);

#define CreateFile __AW_SUFFIXED__(CreateFile)
WINBASEAPI HANDLE WINAPI CreateFileA
(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
WINBASEAPI HANDLE WINAPI CreateFileW
(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

#define CreateFileMapping __AW_SUFFIXED__(CreateFileMapping)
WINBASEAPI HANDLE WINAPI CreateFileMappingA
(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
WINBASEAPI HANDLE WINAPI CreateFileMappingW
(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);

WINBASEAPI HANDLE WINAPI CreateIoCompletionPort
(HANDLE, HANDLE, ULONG_PTR, DWORD);

#define CreateMailslot __AW_SUFFIXED__(CreateMailslot)
WINBASEAPI HANDLE WINAPI CreateMailslotA
(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
WINBASEAPI HANDLE WINAPI CreateMailslotW
(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES);

#define CreateMutex __AW_SUFFIXED__(CreateMutex)
WINBASEAPI HANDLE WINAPI CreateMutexA (LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
WINBASEAPI HANDLE WINAPI CreateMutexW (LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR);

#define CreateNamedPipe __AW_SUFFIXED__(CreateNamedPipe)
WINBASEAPI HANDLE WINAPI CreateNamedPipeA
(LPCSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
WINBASEAPI HANDLE WINAPI CreateNamedPipeW
(LPCWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);

WINBASEAPI BOOL WINAPI CreatePipe
(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
WINBASEAPI BOOL WINAPI CreatePrivateObjectSecurity
( PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR *, BOOL,
  HANDLE, PGENERIC_MAPPING
);

#define CreateProcess __AW_SUFFIXED__(CreateProcess)
WINBASEAPI BOOL WINAPI CreateProcessA
( LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
  PVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION
);
WINBASEAPI BOOL WINAPI CreateProcessW
( LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL,
  DWORD, PVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION
);

#define CreateProcessAsUser __AW_SUFFIXED__(CreateProcessAsUser)
WINBASEAPI BOOL WINAPI CreateProcessAsUserA
( HANDLE, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL,
  DWORD, PVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION
);
WINBASEAPI BOOL WINAPI CreateProcessAsUserW
( HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
  BOOL, DWORD, PVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION
);

WINBASEAPI HANDLE WINAPI CreateRemoteThread
( HANDLE, LPSECURITY_ATTRIBUTES, DWORD, LPTHREAD_START_ROUTINE,
  LPVOID, DWORD, LPDWORD
);

#define CreateSemaphore __AW_SUFFIXED__(CreateSemaphore)
WINBASEAPI HANDLE WINAPI CreateSemaphoreA
(LPSECURITY_ATTRIBUTES, LONG, LONG, LPCSTR);
WINBASEAPI HANDLE WINAPI CreateSemaphoreW
(LPSECURITY_ATTRIBUTES, LONG, LONG, LPCWSTR);

WINBASEAPI DWORD WINAPI CreateTapePartition (HANDLE, DWORD, DWORD, DWORD);
WINBASEAPI HANDLE WINAPI CreateThread
(LPSECURITY_ATTRIBUTES, DWORD, LPTHREAD_START_ROUTINE, PVOID, DWORD, PDWORD);

#define CreateWaitableTimer __AW_SUFFIXED__(CreateWaitableTimer)
WINBASEAPI HANDLE WINAPI CreateWaitableTimerA
(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
WINBASEAPI HANDLE WINAPI CreateWaitableTimerW
(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR);

WINBASEAPI BOOL WINAPI DebugActiveProcess (DWORD);
WINBASEAPI void WINAPI DebugBreak (void);

#define DefineDosDevice __AW_SUFFIXED__(DefineDosDevice)
WINBASEAPI BOOL WINAPI DefineDosDeviceA (DWORD, LPCSTR, LPCSTR);
WINBASEAPI BOOL WINAPI DefineDosDeviceW (DWORD, LPCWSTR, LPCWSTR);

#define DefineHandleTable(w)  ((w), TRUE)

WINBASEAPI BOOL WINAPI DeleteAce (PACL, DWORD);
WINBASEAPI ATOM WINAPI DeleteAtom (ATOM);
WINBASEAPI void WINAPI DeleteCriticalSection (PCRITICAL_SECTION);
WINBASEAPI void WINAPI DeleteFiber (PVOID);

#define DeleteFile __AW_SUFFIXED__(DeleteFile)
WINBASEAPI BOOL WINAPI DeleteFileA (LPCSTR);
WINBASEAPI BOOL WINAPI DeleteFileW (LPCWSTR);

WINBASEAPI BOOL WINAPI DeregisterEventSource (HANDLE);
WINBASEAPI BOOL WINAPI DestroyPrivateObjectSecurity (PSECURITY_DESCRIPTOR *);
WINBASEAPI BOOL WINAPI DeviceIoControl
(HANDLE, DWORD, PVOID, DWORD, PVOID, DWORD, PDWORD, POVERLAPPED);
WINBASEAPI BOOL WINAPI DisableThreadLibraryCalls (HMODULE);
WINBASEAPI BOOL WINAPI DisconnectNamedPipe (HANDLE);
WINBASEAPI BOOL WINAPI DosDateTimeToFileTime (WORD, WORD, LPFILETIME);
WINBASEAPI BOOL WINAPI DuplicateHandle
(HANDLE, HANDLE, HANDLE, PHANDLE, DWORD, BOOL, DWORD);
WINBASEAPI BOOL WINAPI DuplicateToken
(HANDLE, SECURITY_IMPERSONATION_LEVEL, PHANDLE);
WINBASEAPI BOOL WINAPI DuplicateTokenEx
( HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL,
  TOKEN_TYPE, PHANDLE
);

#define EncryptFile __AW_SUFFIXED__(EncryptFile)
WINBASEAPI BOOL WINAPI EncryptFileA (LPCSTR);
WINBASEAPI BOOL WINAPI EncryptFileW (LPCWSTR);

#define EndUpdateResource __AW_SUFFIXED__(EndUpdateResource)
WINBASEAPI BOOL WINAPI EndUpdateResourceA (HANDLE, BOOL);
WINBASEAPI BOOL WINAPI EndUpdateResourceW (HANDLE, BOOL);

WINBASEAPI void WINAPI EnterCriticalSection (LPCRITICAL_SECTION);

#define EnumResourceLanguages __AW_SUFFIXED__(EnumResourceLanguages)
WINBASEAPI BOOL WINAPI EnumResourceLanguagesA
(HMODULE, LPCSTR, LPCSTR, ENUMRESLANGPROCA, LONG_PTR);
WINBASEAPI BOOL WINAPI EnumResourceLanguagesW
(HMODULE, LPCWSTR, LPCWSTR, ENUMRESLANGPROCW, LONG_PTR);

#define EnumResourceNames __AW_SUFFIXED__(EnumResourceNames)
WINBASEAPI BOOL WINAPI EnumResourceNamesA
(HMODULE, LPCSTR, ENUMRESNAMEPROCA, LONG_PTR);
WINBASEAPI BOOL WINAPI EnumResourceNamesW
(HMODULE, LPCWSTR, ENUMRESNAMEPROCW, LONG_PTR);

#define EnumResourceTypes __AW_SUFFIXED__(EnumResourceTypes)
WINBASEAPI BOOL WINAPI EnumResourceTypesA (HMODULE, ENUMRESTYPEPROCA, LONG_PTR);
WINBASEAPI BOOL WINAPI EnumResourceTypesW (HMODULE, ENUMRESTYPEPROCW, LONG_PTR);

WINBASEAPI BOOL WINAPI EqualPrefixSid (PSID, PSID);
WINBASEAPI BOOL WINAPI EqualSid (PSID, PSID);
WINBASEAPI DWORD WINAPI EraseTape (HANDLE, DWORD, BOOL);
WINBASEAPI BOOL WINAPI EscapeCommFunction (HANDLE, DWORD);
DECLSPEC_NORETURN WINBASEAPI void WINAPI ExitProcess (UINT);
DECLSPEC_NORETURN WINBASEAPI void WINAPI ExitThread (DWORD);

#define ExpandEnvironmentStrings __AW_SUFFIXED__(ExpandEnvironmentStrings)
WINBASEAPI DWORD WINAPI ExpandEnvironmentStringsA (LPCSTR, LPSTR, DWORD);
WINBASEAPI DWORD WINAPI ExpandEnvironmentStringsW (LPCWSTR, LPWSTR, DWORD);

#define FatalAppExit __AW_SUFFIXED__(FatalAppExit)
WINBASEAPI void WINAPI FatalAppExitA (UINT, LPCSTR);
WINBASEAPI void WINAPI FatalAppExitW (UINT, LPCWSTR);

WINBASEAPI void WINAPI FatalExit (int);

#define FileEncryptionStatus __AW_SUFFIXED__(FileEncryptionStatus)
WINBASEAPI BOOL WINAPI FileEncryptionStatusA (LPCSTR, LPDWORD);
WINBASEAPI BOOL WINAPI FileEncryptionStatusW (LPCWSTR, LPDWORD);

WINBASEAPI BOOL WINAPI FileTimeToDosDateTime (CONST FILETIME *, LPWORD, LPWORD);
WINBASEAPI BOOL WINAPI FileTimeToLocalFileTime (CONST FILETIME *, LPFILETIME);
WINBASEAPI BOOL WINAPI FileTimeToSystemTime (CONST FILETIME *, LPSYSTEMTIME);

#define FindAtom __AW_SUFFIXED__(FindAtom)
WINBASEAPI ATOM WINAPI FindAtomA (LPCSTR);
WINBASEAPI ATOM WINAPI FindAtomW (LPCWSTR);

WINBASEAPI BOOL WINAPI FindClose (HANDLE);
WINBASEAPI BOOL WINAPI FindCloseChangeNotification (HANDLE);

#define FindFirstChangeNotification __AW_SUFFIXED__(FindFirstChangeNotification)
WINBASEAPI HANDLE WINAPI FindFirstChangeNotificationA (LPCSTR, BOOL, DWORD);
WINBASEAPI HANDLE WINAPI FindFirstChangeNotificationW (LPCWSTR, BOOL, DWORD);

#define FindFirstFile __AW_SUFFIXED__(FindFirstFile)
WINBASEAPI HANDLE WINAPI FindFirstFileA (LPCSTR, LPWIN32_FIND_DATAA);
WINBASEAPI HANDLE WINAPI FindFirstFileW (LPCWSTR, LPWIN32_FIND_DATAW);

#define FindFirstFileEx __AW_SUFFIXED__(FindFirstFileEx)
WINBASEAPI HANDLE WINAPI FindFirstFileExA
(LPCSTR, FINDEX_INFO_LEVELS, PVOID, FINDEX_SEARCH_OPS, PVOID, DWORD);
WINBASEAPI HANDLE WINAPI FindFirstFileExW
(LPCWSTR, FINDEX_INFO_LEVELS, PVOID, FINDEX_SEARCH_OPS, PVOID, DWORD);

WINBASEAPI BOOL WINAPI FindFirstFreeAce (PACL, PVOID *);
WINBASEAPI BOOL WINAPI FindNextChangeNotification (HANDLE);

#define FindNextFile __AW_SUFFIXED__(FindNextFile)
WINBASEAPI BOOL WINAPI FindNextFileA (HANDLE, LPWIN32_FIND_DATAA);
WINBASEAPI BOOL WINAPI FindNextFileW (HANDLE, LPWIN32_FIND_DATAW);

#define FindResource __AW_SUFFIXED__(FindResource)
WINBASEAPI HRSRC WINAPI FindResourceA (HMODULE, LPCSTR, LPCSTR);
WINBASEAPI HRSRC WINAPI FindResourceW (HINSTANCE, LPCWSTR, LPCWSTR);

#define FindResourceEx __AW_SUFFIXED__(FindResourceEx)
WINBASEAPI HRSRC WINAPI FindResourceExA (HINSTANCE, LPCSTR, LPCSTR, WORD);
WINBASEAPI HRSRC WINAPI FindResourceExW (HINSTANCE, LPCWSTR, LPCWSTR, WORD);

WINBASEAPI BOOL WINAPI FlushFileBuffers (HANDLE);
WINBASEAPI BOOL WINAPI FlushInstructionCache (HANDLE, PCVOID, DWORD);
WINBASEAPI BOOL WINAPI FlushViewOfFile (PCVOID, DWORD);

#define FormatMessage __AW_SUFFIXED__(FormatMessage)
WINBASEAPI DWORD WINAPI FormatMessageA
(DWORD, PCVOID, DWORD, DWORD, LPSTR, DWORD, va_list *);
WINBASEAPI DWORD WINAPI FormatMessageW
(DWORD, PCVOID, DWORD, DWORD, LPWSTR, DWORD, va_list *);

#define FreeEnvironmentStrings __AW_SUFFIXED__(FreeEnvironmentStrings)
WINBASEAPI BOOL WINAPI FreeEnvironmentStringsA (LPSTR);
WINBASEAPI BOOL WINAPI FreeEnvironmentStringsW (LPWSTR);

WINBASEAPI BOOL WINAPI FreeLibrary (HMODULE);
DECLSPEC_NORETURN WINBASEAPI void WINAPI FreeLibraryAndExitThread
(HMODULE, DWORD);

#define FreeModule(m)	     FreeLibrary(m)
#define FreeProcInstance(p)  (void)(p)

#ifndef XFree86Server
WINBASEAPI BOOL WINAPI FreeResource (HGLOBAL);
#endif /* ndef XFree86Server */

WINBASEAPI PVOID WINAPI FreeSid (PSID);
WINBASEAPI BOOL WINAPI GetAce (PACL, DWORD, LPVOID *);
WINBASEAPI BOOL WINAPI GetAclInformation
(PACL, PVOID, DWORD, ACL_INFORMATION_CLASS);

#define GetAtomName __AW_SUFFIXED__(GetAtomName)
WINBASEAPI UINT WINAPI GetAtomNameA (ATOM, LPSTR, int);
WINBASEAPI UINT WINAPI GetAtomNameW (ATOM, LPWSTR, int);

#define GetBinaryType __AW_SUFFIXED__(GetBinaryType)
WINBASEAPI BOOL WINAPI GetBinaryTypeA (LPCSTR, PDWORD);
WINBASEAPI BOOL WINAPI GetBinaryTypeW (LPCWSTR, PDWORD);

#define GetCommandLine __AW_SUFFIXED__(GetCommandLine)
WINBASEAPI LPSTR WINAPI GetCommandLineA (VOID);
WINBASEAPI LPWSTR WINAPI GetCommandLineW (VOID);

WINBASEAPI BOOL WINAPI GetCommConfig (HANDLE, LPCOMMCONFIG, PDWORD);
WINBASEAPI BOOL WINAPI GetCommMask (HANDLE, PDWORD);
WINBASEAPI BOOL WINAPI GetCommModemStatus (HANDLE, PDWORD);
WINBASEAPI BOOL WINAPI GetCommProperties (HANDLE, LPCOMMPROP);
WINBASEAPI BOOL WINAPI GetCommState (HANDLE, LPDCB);
WINBASEAPI BOOL WINAPI GetCommTimeouts (HANDLE, LPCOMMTIMEOUTS);

#define GetCompressedFileSize __AW_SUFFIXED__(GetCompressedFileSize)
WINBASEAPI DWORD WINAPI GetCompressedFileSizeA (LPCSTR, PDWORD);
WINBASEAPI DWORD WINAPI GetCompressedFileSizeW (LPCWSTR, PDWORD);

#define GetComputerName __AW_SUFFIXED__(GetComputerName)
WINBASEAPI BOOL WINAPI GetComputerNameA (LPSTR, PDWORD);
WINBASEAPI BOOL WINAPI GetComputerNameW (LPWSTR, PDWORD);

#define GetCurrentDirectory __AW_SUFFIXED__(GetCurrentDirectory)
WINBASEAPI DWORD WINAPI GetCurrentDirectoryA (DWORD, LPSTR);
WINBASEAPI DWORD WINAPI GetCurrentDirectoryW (DWORD, LPWSTR);

/* GetCurrentHwProfile: previously missing UNICODE vs. ANSI define */
#define GetCurrentHwProfile __AW_SUFFIXED__(GetCurrentHwProfile)
WINBASEAPI BOOL WINAPI GetCurrentHwProfileA (LPHW_PROFILE_INFOA);
WINBASEAPI BOOL WINAPI GetCurrentHwProfileW (LPHW_PROFILE_INFOW);

WINBASEAPI HANDLE WINAPI GetCurrentProcess (void);
WINBASEAPI DWORD WINAPI GetCurrentProcessId (void);
WINBASEAPI HANDLE WINAPI GetCurrentThread (void);

#ifdef _WIN32_WCE
extern DWORD GetCurrentThreadId (void);
#else
WINBASEAPI DWORD WINAPI GetCurrentThreadId (void);
#endif

#define GetCurrentTime  GetTickCount

#define GetDefaultCommConfig __AW_SUFFIXED__(GetDefaultCommConfig)
WINBASEAPI BOOL WINAPI GetDefaultCommConfigA (LPCSTR, LPCOMMCONFIG, PDWORD);
WINBASEAPI BOOL WINAPI GetDefaultCommConfigW (LPCWSTR, LPCOMMCONFIG, PDWORD);

WINBASEAPI BOOL WINAPI GetDevicePowerState (HANDLE, BOOL *);

#define GetDiskFreeSpace __AW_SUFFIXED__(GetDiskFreeSpace)
WINBASEAPI BOOL WINAPI GetDiskFreeSpaceA
(LPCSTR, PDWORD, PDWORD, PDWORD, PDWORD);
WINBASEAPI BOOL WINAPI GetDiskFreeSpaceW
(LPCWSTR, PDWORD, PDWORD, PDWORD, PDWORD);

#define GetDiskFreeSpaceEx __AW_SUFFIXED__(GetDiskFreeSpaceEx)
WINBASEAPI BOOL WINAPI GetDiskFreeSpaceExA
(LPCSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER);
WINBASEAPI BOOL WINAPI GetDiskFreeSpaceExW
(LPCWSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER);

#define GetDriveType __AW_SUFFIXED__(GetDriveType)
WINBASEAPI UINT WINAPI GetDriveTypeA (LPCSTR);
WINBASEAPI UINT WINAPI GetDriveTypeW (LPCWSTR);

WINBASEAPI LPCH WINAPI GetEnvironmentStrings (void);

#define GetEnvironmentStrings __AW_SUFFIXED__(GetEnvironmentStrings)
WINBASEAPI LPCH WINAPI GetEnvironmentStringsA (void);
WINBASEAPI LPWCH WINAPI GetEnvironmentStringsW (void);

#define GetEnvironmentVariable __AW_SUFFIXED__(GetEnvironmentVariable)
WINBASEAPI DWORD WINAPI GetEnvironmentVariableA (LPCSTR, LPSTR, DWORD);
WINBASEAPI DWORD WINAPI GetEnvironmentVariableW (LPCWSTR, LPWSTR, DWORD);

WINBASEAPI BOOL WINAPI GetExitCodeProcess (HANDLE, PDWORD);
WINBASEAPI BOOL WINAPI GetExitCodeThread (HANDLE, PDWORD);

#define GetFileAttributes __AW_SUFFIXED__(GetFileAttributes)
WINBASEAPI DWORD WINAPI GetFileAttributesA (LPCSTR);
WINBASEAPI DWORD WINAPI GetFileAttributesW (LPCWSTR);

#define GetFileAttributesEx __AW_SUFFIXED__(GetFileAttributesEx)
WINBASEAPI BOOL WINAPI GetFileAttributesExA
(LPCSTR, GET_FILEEX_INFO_LEVELS, PVOID);
WINBASEAPI BOOL WINAPI GetFileAttributesExW
(LPCWSTR, GET_FILEEX_INFO_LEVELS, PVOID);

WINBASEAPI BOOL WINAPI GetFileInformationByHandle
(HANDLE, LPBY_HANDLE_FILE_INFORMATION);

#define GetFileSecurity __AW_SUFFIXED__(GetFileSecurity)
WINBASEAPI BOOL WINAPI GetFileSecurityA
(LPCSTR, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, DWORD, PDWORD);
WINBASEAPI BOOL WINAPI GetFileSecurityW
(LPCWSTR, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, DWORD, PDWORD);

WINBASEAPI DWORD WINAPI GetFileSize (HANDLE, PDWORD);
WINBASEAPI BOOL WINAPI GetFileTime (HANDLE, LPFILETIME, LPFILETIME, LPFILETIME);
WINBASEAPI DWORD WINAPI GetFileType (HANDLE);

#define GetFreeSpace(w)  (0x100000L)

#define GetFullPathName __AW_SUFFIXED__(GetFullPathName)
WINBASEAPI DWORD WINAPI GetFullPathNameA (LPCSTR, DWORD, LPSTR, LPSTR *);
WINBASEAPI DWORD WINAPI GetFullPathNameW (LPCWSTR, DWORD, LPWSTR, LPWSTR *);

WINBASEAPI BOOL WINAPI GetHandleInformation (HANDLE, PDWORD);
WINBASEAPI BOOL WINAPI GetKernelObjectSecurity
(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, DWORD, PDWORD);
WINBASEAPI DWORD WINAPI GetLastError (void);
WINBASEAPI DWORD WINAPI GetLengthSid (PSID);
WINBASEAPI void WINAPI GetLocalTime (LPSYSTEMTIME);
WINBASEAPI DWORD WINAPI GetLogicalDrives (void);

#define GetLogicalDriveStrings __AW_SUFFIXED__(GetLogicalDriveStrings)
WINBASEAPI DWORD WINAPI GetLogicalDriveStringsA (DWORD, LPSTR);
WINBASEAPI DWORD WINAPI GetLogicalDriveStringsW (DWORD, LPWSTR);

WINBASEAPI BOOL WINAPI GetMailslotInfo (HANDLE, PDWORD, PDWORD, PDWORD, PDWORD);

#define GetModuleFileName __AW_SUFFIXED__(GetModuleFileName)
WINBASEAPI DWORD WINAPI GetModuleFileNameA (HINSTANCE, LPSTR, DWORD);
WINBASEAPI DWORD WINAPI GetModuleFileNameW (HINSTANCE, LPWSTR, DWORD);

#define GetModuleHandle __AW_SUFFIXED__(GetModuleHandle)
WINBASEAPI HMODULE WINAPI GetModuleHandleA (LPCSTR);
WINBASEAPI HMODULE WINAPI GetModuleHandleW (LPCWSTR);

#define GetNamedPipeHandleState __AW_SUFFIXED__(GetNamedPipeHandleState)
WINBASEAPI BOOL WINAPI GetNamedPipeHandleStateA
(HANDLE, PDWORD, PDWORD, PDWORD, PDWORD, LPSTR, DWORD);
WINBASEAPI BOOL WINAPI GetNamedPipeHandleStateW
(HANDLE, PDWORD, PDWORD, PDWORD, PDWORD, LPWSTR, DWORD);

WINBASEAPI BOOL WINAPI GetNamedPipeInfo
(HANDLE, PDWORD, PDWORD, PDWORD, PDWORD);
WINBASEAPI BOOL WINAPI GetNumberOfEventLogRecords (HANDLE, PDWORD);
WINBASEAPI BOOL WINAPI GetOldestEventLogRecord (HANDLE, PDWORD);
WINBASEAPI BOOL WINAPI GetOverlappedResult (HANDLE, LPOVERLAPPED, PDWORD, BOOL);
WINBASEAPI DWORD WINAPI GetPriorityClass (HANDLE);
WINBASEAPI BOOL WINAPI GetPrivateObjectSecurity
( PSECURITY_DESCRIPTOR, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
  DWORD, PDWORD
);

#define GetPrivateProfileInt __AW_SUFFIXED__(GetPrivateProfileInt)
WINBASEAPI UINT WINAPI GetPrivateProfileIntA (LPCSTR, LPCSTR, INT, LPCSTR);
WINBASEAPI UINT WINAPI GetPrivateProfileIntW (LPCWSTR, LPCWSTR, INT, LPCWSTR);

#define GetPrivateProfileSection __AW_SUFFIXED__(GetPrivateProfileSection)
WINBASEAPI DWORD WINAPI GetPrivateProfileSectionA
(LPCSTR, LPSTR, DWORD, LPCSTR);
WINBASEAPI DWORD WINAPI GetPrivateProfileSectionW
(LPCWSTR, LPWSTR, DWORD, LPCWSTR);

#define \
GetPrivateProfileSectionNames __AW_SUFFIXED__(GetPrivateProfileSectionNames)
WINBASEAPI DWORD WINAPI GetPrivateProfileSectionNamesA (LPSTR, DWORD, LPCSTR);
WINBASEAPI DWORD WINAPI GetPrivateProfileSectionNamesW (LPWSTR, DWORD, LPCWSTR);

#define GetPrivateProfileString __AW_SUFFIXED__(GetPrivateProfileString)
WINBASEAPI DWORD WINAPI GetPrivateProfileStringA
(LPCSTR, LPCSTR, LPCSTR, LPSTR, DWORD, LPCSTR);
WINBASEAPI DWORD WINAPI GetPrivateProfileStringW
(LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, DWORD, LPCWSTR);

#define GetPrivateProfileStruct __AW_SUFFIXED__(GetPrivateProfileStruct)
WINBASEAPI BOOL WINAPI GetPrivateProfileStructA
(LPCSTR, LPCSTR, LPVOID, UINT, LPCSTR);
WINBASEAPI BOOL WINAPI GetPrivateProfileStructW
(LPCWSTR, LPCWSTR, LPVOID, UINT, LPCWSTR);

WINBASEAPI FARPROC WINAPI GetProcAddress (HINSTANCE, LPCSTR);
WINBASEAPI BOOL WINAPI GetProcessAffinityMask (HANDLE, PDWORD, PDWORD);

WINBASEAPI HANDLE WINAPI GetProcessHeap (VOID);
WINBASEAPI DWORD WINAPI GetProcessHeaps (DWORD, PHANDLE);
WINBASEAPI BOOL WINAPI GetProcessPriorityBoost (HANDLE, PBOOL);
WINBASEAPI BOOL WINAPI GetProcessShutdownParameters (PDWORD, PDWORD);
WINBASEAPI BOOL WINAPI GetProcessTimes
(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME, LPFILETIME);
WINBASEAPI DWORD WINAPI GetProcessVersion (DWORD);
WINBASEAPI HWINSTA WINAPI GetProcessWindowStation (void);
WINBASEAPI BOOL WINAPI GetProcessWorkingSetSize (HANDLE, PSIZE_T, PSIZE_T);

#define GetProfileInt __AW_SUFFIXED__(GetProfileInt)
WINBASEAPI UINT WINAPI GetProfileIntA (LPCSTR, LPCSTR, INT);
WINBASEAPI UINT WINAPI GetProfileIntW (LPCWSTR, LPCWSTR, INT);

#define GetProfileSection __AW_SUFFIXED__(GetProfileSection)
WINBASEAPI DWORD WINAPI GetProfileSectionA (LPCSTR, LPSTR, DWORD);
WINBASEAPI DWORD WINAPI GetProfileSectionW (LPCWSTR, LPWSTR, DWORD);

#define GetProfileString __AW_SUFFIXED__(GetProfileString)
WINBASEAPI DWORD WINAPI GetProfileStringA
(LPCSTR, LPCSTR, LPCSTR, LPSTR, DWORD);
WINBASEAPI DWORD WINAPI GetProfileStringW
(LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, DWORD);

WINBASEAPI BOOL WINAPI GetQueuedCompletionStatus
(HANDLE, PDWORD, PULONG_PTR, LPOVERLAPPED *, DWORD);
WINBASEAPI BOOL WINAPI GetSecurityDescriptorControl
(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR_CONTROL, PDWORD);
WINBASEAPI BOOL WINAPI GetSecurityDescriptorDacl
(PSECURITY_DESCRIPTOR, LPBOOL, PACL *, LPBOOL);
WINBASEAPI BOOL WINAPI GetSecurityDescriptorGroup
(PSECURITY_DESCRIPTOR, PSID *, LPBOOL);
WINBASEAPI DWORD WINAPI GetSecurityDescriptorLength (PSECURITY_DESCRIPTOR);
WINBASEAPI BOOL WINAPI GetSecurityDescriptorOwner
(PSECURITY_DESCRIPTOR, PSID *, LPBOOL);
WINBASEAPI BOOL WINAPI GetSecurityDescriptorSacl
(PSECURITY_DESCRIPTOR, LPBOOL, PACL *, LPBOOL);

#define GetShortPathName __AW_SUFFIXED__(GetShortPathName)
WINBASEAPI DWORD WINAPI GetShortPathNameA (LPCSTR, LPSTR, DWORD);
WINBASEAPI DWORD WINAPI GetShortPathNameW (LPCWSTR, LPWSTR, DWORD);

WINBASEAPI PSID_IDENTIFIER_AUTHORITY WINAPI GetSidIdentifierAuthority (PSID);
WINBASEAPI DWORD WINAPI GetSidLengthRequired (UCHAR);
WINBASEAPI PDWORD WINAPI GetSidSubAuthority (PSID, DWORD);
WINBASEAPI PUCHAR WINAPI GetSidSubAuthorityCount (PSID);

#define GetStartupInfo __AW_SUFFIXED__(GetStartupInfo)
WINBASEAPI VOID WINAPI GetStartupInfoA (LPSTARTUPINFOA);
WINBASEAPI VOID WINAPI GetStartupInfoW (LPSTARTUPINFOW);

WINBASEAPI HANDLE WINAPI GetStdHandle (DWORD);

#define GetSystemDirectory __AW_SUFFIXED__(GetSystemDirectory)
WINBASEAPI UINT WINAPI GetSystemDirectoryA (LPSTR, UINT);
WINBASEAPI UINT WINAPI GetSystemDirectoryW (LPWSTR, UINT);

WINBASEAPI VOID WINAPI GetSystemInfo (LPSYSTEM_INFO);
WINBASEAPI BOOL WINAPI GetSystemPowerStatus (LPSYSTEM_POWER_STATUS);
WINBASEAPI VOID WINAPI GetSystemTime (LPSYSTEMTIME);
WINBASEAPI BOOL WINAPI GetSystemTimeAdjustment (PDWORD, PDWORD, PBOOL);
WINBASEAPI void WINAPI GetSystemTimeAsFileTime (LPFILETIME);
WINBASEAPI DWORD WINAPI GetTapeParameters (HANDLE, DWORD, PDWORD, PVOID);
WINBASEAPI DWORD WINAPI GetTapePosition (HANDLE, DWORD, PDWORD, PDWORD, PDWORD);
WINBASEAPI DWORD WINAPI GetTapeStatus (HANDLE);

#define GetTempFileName __AW_SUFFIXED__(GetTempFileName)
WINBASEAPI UINT WINAPI GetTempFileNameA (LPCSTR, LPCSTR, UINT, LPSTR);
WINBASEAPI UINT WINAPI GetTempFileNameW (LPCWSTR, LPCWSTR, UINT, LPWSTR);

#define GetTempPath __AW_SUFFIXED__(GetTempPath)
WINBASEAPI DWORD WINAPI GetTempPathA (DWORD, LPSTR);
WINBASEAPI DWORD WINAPI GetTempPathW (DWORD, LPWSTR);

WINBASEAPI BOOL WINAPI GetThreadContext (HANDLE, LPCONTEXT);
WINBASEAPI int WINAPI GetThreadPriority (HANDLE);
WINBASEAPI BOOL WINAPI GetThreadPriorityBoost (HANDLE, PBOOL);
WINBASEAPI BOOL WINAPI GetThreadSelectorEntry (HANDLE, DWORD, LPLDT_ENTRY);
WINBASEAPI BOOL WINAPI GetThreadTimes
(HANDLE, LPFILETIME, LPFILETIME, LPFILETIME, LPFILETIME);
WINBASEAPI DWORD WINAPI GetTickCount (VOID);
WINBASEAPI DWORD WINAPI GetTimeZoneInformation (LPTIME_ZONE_INFORMATION);
WINBASEAPI BOOL WINAPI GetTokenInformation
(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, DWORD, PDWORD);

#define GetUserName __AW_SUFFIXED__(GetUserName)
WINBASEAPI BOOL WINAPI GetUserNameA (LPSTR, PDWORD);
WINBASEAPI BOOL WINAPI GetUserNameW (LPWSTR, PDWORD);

WINBASEAPI DWORD WINAPI GetVersion (void);

#define GetVersionEx __AW_SUFFIXED__(GetVersionEx)
WINBASEAPI BOOL WINAPI GetVersionExA (LPOSVERSIONINFOA);
WINBASEAPI BOOL WINAPI GetVersionExW (LPOSVERSIONINFOW);

#define GetVolumeInformation __AW_SUFFIXED__(GetVolumeInformation)
WINBASEAPI BOOL WINAPI GetVolumeInformationA
(LPCSTR, LPSTR, DWORD, PDWORD, PDWORD, PDWORD, LPSTR, DWORD);
WINBASEAPI BOOL WINAPI GetVolumeInformationW
(LPCWSTR, LPWSTR, DWORD, PDWORD, PDWORD, PDWORD, LPWSTR, DWORD);

#define GetWindowsDirectory __AW_SUFFIXED__(GetWindowsDirectory)
WINBASEAPI UINT WINAPI GetWindowsDirectoryA (LPSTR, UINT);
WINBASEAPI UINT WINAPI GetWindowsDirectoryW (LPWSTR, UINT);

WINBASEAPI DWORD WINAPI GetWindowThreadProcessId (HWND, PDWORD);
WINBASEAPI UINT WINAPI GetWriteWatch
(DWORD, PVOID, SIZE_T, PVOID *, PULONG_PTR, PULONG);

#define GlobalAddAtom __AW_SUFFIXED__(GlobalAddAtom)
WINBASEAPI ATOM WINAPI GlobalAddAtomA (LPCSTR);
WINBASEAPI ATOM WINAPI GlobalAddAtomW (LPCWSTR);

WINBASEAPI HGLOBAL WINAPI GlobalAlloc (UINT, DWORD);
WINBASEAPI SIZE_T WINAPI GlobalCompact (DWORD); /* Obsolete: Has no effect. */
WINBASEAPI ATOM WINAPI GlobalDeleteAtom (ATOM);

#define GlobalDiscard(hMem)  GlobalReAlloc((hMem), 0, GMEM_MOVEABLE)

#define GlobalFindAtom __AW_SUFFIXED__(GlobalFindAtom)
WINBASEAPI ATOM WINAPI GlobalFindAtomA (LPCSTR);
WINBASEAPI ATOM WINAPI GlobalFindAtomW (LPCWSTR);

WINBASEAPI VOID WINAPI GlobalFix (HGLOBAL); /* Obsolete: Has no effect. */
WINBASEAPI UINT WINAPI GlobalFlags (HGLOBAL); /* Obsolete: Has no effect. */
WINBASEAPI HGLOBAL WINAPI GlobalFree (HGLOBAL);

#define GlobalGetAtomName __AW_SUFFIXED__(GlobalGetAtomName)
WINBASEAPI UINT WINAPI GlobalGetAtomNameA (ATOM, LPSTR, int);
WINBASEAPI UINT WINAPI GlobalGetAtomNameW (ATOM, LPWSTR, int);

WINBASEAPI HGLOBAL WINAPI GlobalHandle (PCVOID);
WINBASEAPI LPVOID WINAPI GlobalLock (HGLOBAL);
WINBASEAPI VOID WINAPI GlobalMemoryStatus (LPMEMORYSTATUS);
WINBASEAPI HGLOBAL WINAPI GlobalReAlloc (HGLOBAL, DWORD, UINT);
WINBASEAPI DWORD WINAPI GlobalSize (HGLOBAL);
WINBASEAPI VOID WINAPI GlobalUnfix (HGLOBAL); /* Obsolete: Has no effect. */
WINBASEAPI BOOL WINAPI GlobalUnlock (HGLOBAL);
WINBASEAPI BOOL WINAPI GlobalUnWire (HGLOBAL); /* Obsolete: Has no effect. */
WINBASEAPI PVOID WINAPI GlobalWire (HGLOBAL); /* Obsolete: Has no effect. */

#define HasOverlappedIoCompleted(lpOverlapped)  \
  ((lpOverlapped)->Internal != STATUS_PENDING)

WINBASEAPI PVOID WINAPI HeapAlloc (HANDLE, DWORD, DWORD);
SIZE_T WINAPI HeapCompact (HANDLE, DWORD);
WINBASEAPI HANDLE WINAPI HeapCreate (DWORD, DWORD, DWORD);
WINBASEAPI BOOL WINAPI HeapDestroy (HANDLE);
WINBASEAPI BOOL WINAPI HeapFree (HANDLE, DWORD, PVOID);
WINBASEAPI BOOL WINAPI HeapLock (HANDLE);
WINBASEAPI PVOID WINAPI HeapReAlloc (HANDLE, DWORD, PVOID, DWORD);
WINBASEAPI DWORD WINAPI HeapSize (HANDLE, DWORD, PCVOID);
WINBASEAPI BOOL WINAPI HeapUnlock (HANDLE);
WINBASEAPI BOOL WINAPI HeapValidate (HANDLE, DWORD, PCVOID);
WINBASEAPI BOOL WINAPI HeapWalk (HANDLE, LPPROCESS_HEAP_ENTRY);
WINBASEAPI BOOL WINAPI ImpersonateLoggedOnUser (HANDLE);
WINBASEAPI BOOL WINAPI ImpersonateNamedPipeClient (HANDLE);
WINBASEAPI BOOL WINAPI ImpersonateSelf (SECURITY_IMPERSONATION_LEVEL);
WINBASEAPI BOOL WINAPI InitAtomTable (DWORD);
WINBASEAPI BOOL WINAPI InitializeAcl (PACL, DWORD, DWORD);
WINBASEAPI VOID WINAPI InitializeCriticalSection (LPCRITICAL_SECTION);
WINBASEAPI BOOL WINAPI InitializeCriticalSectionAndSpinCount
(LPCRITICAL_SECTION, DWORD);
WINBASEAPI DWORD WINAPI SetCriticalSectionSpinCount (LPCRITICAL_SECTION, DWORD);
WINBASEAPI BOOL WINAPI InitializeSecurityDescriptor
(PSECURITY_DESCRIPTOR, DWORD);
WINBASEAPI BOOL WINAPI InitializeSid (PSID, PSID_IDENTIFIER_AUTHORITY, BYTE);

#if !(__USE_NTOSKRNL__)
/* CAREFUL: These are exported from ntoskrnl.exe and declared in winddk.h
   as __fastcall functions, but are  exported from kernel32.dll as __stdcall */
#if (_WIN32_WINNT >= 0x0501)
WINBASEAPI VOID WINAPI InitializeSListHead (PSLIST_HEADER);
#endif

#ifndef __INTERLOCKED_DECLARED
/* FIXME: Is this another invitation for inconsistent definition?
 * Where else is this declared?
 */
#define __INTERLOCKED_DECLARED
LONG WINAPI InterlockedCompareExchange (LONG volatile *, LONG, LONG);
/* PVOID WINAPI InterlockedCompareExchangePointer (PVOID *, PVOID, PVOID); */
#define InterlockedCompareExchangePointer(d, e, c)  \
  (PVOID)InterlockedCompareExchange((LONG volatile *)(d),(LONG)(e),(LONG)(c))
LONG WINAPI InterlockedDecrement (LONG volatile *);
LONG WINAPI InterlockedExchange (LONG volatile *, LONG);
/* PVOID WINAPI InterlockedExchangePointer (PVOID *, PVOID); */
#define InterlockedExchangePointer(t, v)  \
  (PVOID)InterlockedExchange((LONG volatile *)(t),(LONG)(v))
LONG WINAPI InterlockedExchangeAdd (LONG volatile *, LONG);

#if (_WIN32_WINNT >= 0x0501)
PSLIST_ENTRY WINAPI InterlockedFlushSList (PSLIST_HEADER);
#endif

LONG WINAPI InterlockedIncrement (LONG volatile *);

#if (_WIN32_WINNT >= 0x0501)
PSLIST_ENTRY WINAPI InterlockedPopEntrySList (PSLIST_HEADER);
PSLIST_ENTRY WINAPI InterlockedPushEntrySList (PSLIST_HEADER, PSLIST_ENTRY);
#endif
#endif /* __INTERLOCKED_DECLARED */
#endif /*  __USE_NTOSKRNL__ */

WINBASEAPI BOOL WINAPI IsBadCodePtr (FARPROC);
WINBASEAPI BOOL WINAPI IsBadHugeReadPtr (PCVOID, UINT);
WINBASEAPI BOOL WINAPI IsBadHugeWritePtr (PVOID, UINT);
WINBASEAPI BOOL WINAPI IsBadReadPtr (PCVOID, UINT);

#define IsBadStringPtr __AW_SUFFIXED__(IsBadStringPtr)
WINBASEAPI BOOL WINAPI IsBadStringPtrA (LPCSTR, UINT);
WINBASEAPI BOOL WINAPI IsBadStringPtrW (LPCWSTR, UINT);

WINBASEAPI BOOL WINAPI IsBadWritePtr (PVOID, UINT);
WINBASEAPI BOOL WINAPI IsDebuggerPresent (void);
WINBASEAPI BOOL WINAPI IsProcessorFeaturePresent (DWORD);
WINBASEAPI BOOL WINAPI IsSystemResumeAutomatic (void);
WINBASEAPI BOOL WINAPI IsTextUnicode (PCVOID, int, LPINT);
WINBASEAPI BOOL WINAPI IsValidAcl (PACL);
WINBASEAPI BOOL WINAPI IsValidSecurityDescriptor (PSECURITY_DESCRIPTOR);
WINBASEAPI BOOL WINAPI IsValidSid (PSID);

WINBASEAPI void WINAPI LeaveCriticalSection (LPCRITICAL_SECTION);

#define LimitEmsPages(n)

#define LoadLibrary __AW_SUFFIXED__(LoadLibrary)
WINBASEAPI HINSTANCE WINAPI LoadLibraryA (LPCSTR);
WINBASEAPI HINSTANCE WINAPI LoadLibraryW (LPCWSTR);

#define LoadLibraryEx __AW_SUFFIXED__(LoadLibraryEx)
WINBASEAPI HINSTANCE WINAPI LoadLibraryExA (LPCSTR, HANDLE, DWORD);
WINBASEAPI HINSTANCE WINAPI LoadLibraryExW (LPCWSTR, HANDLE, DWORD);

WINBASEAPI DWORD WINAPI LoadModule (LPCSTR, PVOID);
WINBASEAPI HGLOBAL WINAPI LoadResource (HINSTANCE, HRSRC);
WINBASEAPI HLOCAL WINAPI LocalAlloc (UINT, SIZE_T);
WINBASEAPI SIZE_T WINAPI LocalCompact (UINT); /* Obsolete: Has no effect. */
WINBASEAPI HLOCAL LocalDiscard (HLOCAL);
WINBASEAPI BOOL WINAPI LocalFileTimeToFileTime (CONST FILETIME *, LPFILETIME);
WINBASEAPI UINT WINAPI LocalFlags (HLOCAL); /* Obsolete: Has no effect. */
WINBASEAPI HLOCAL WINAPI LocalFree (HLOCAL);
WINBASEAPI HLOCAL WINAPI LocalHandle (LPCVOID);
WINBASEAPI PVOID WINAPI LocalLock (HLOCAL);
WINBASEAPI HLOCAL WINAPI LocalReAlloc (HLOCAL, SIZE_T, UINT);
WINBASEAPI SIZE_T WINAPI LocalShrink (HLOCAL, UINT);  /* Obsolete: Has no effect. */
WINBASEAPI UINT WINAPI LocalSize (HLOCAL);
WINBASEAPI BOOL WINAPI LocalUnlock (HLOCAL);
WINBASEAPI BOOL WINAPI LockFile (HANDLE, DWORD, DWORD, DWORD, DWORD);
WINBASEAPI BOOL WINAPI LockFileEx
(HANDLE, DWORD, DWORD, DWORD, DWORD, LPOVERLAPPED);
WINBASEAPI PVOID WINAPI LockResource (HGLOBAL);

#define LockSegment(w)  GlobalFix((HANDLE)(w)) /* Obsolete: Has no effect. */

#define LogonUser __AW_SUFFIXED__(LogonUser)
WINBASEAPI BOOL WINAPI LogonUserA (LPSTR, LPSTR, LPSTR, DWORD, DWORD, PHANDLE);
WINBASEAPI BOOL WINAPI LogonUserW
(LPWSTR, LPWSTR, LPWSTR, DWORD, DWORD, PHANDLE);

#define LookupAccountName __AW_SUFFIXED__(LookupAccountName)
WINBASEAPI BOOL WINAPI LookupAccountNameA
(LPCSTR, LPCSTR, PSID, PDWORD, LPSTR, PDWORD, PSID_NAME_USE);
WINBASEAPI BOOL WINAPI LookupAccountNameW
(LPCWSTR, LPCWSTR, PSID, PDWORD, LPWSTR, PDWORD, PSID_NAME_USE);

#define LookupAccountSid __AW_SUFFIXED__(LookupAccountSid)
WINBASEAPI BOOL WINAPI LookupAccountSidA
(LPCSTR, PSID, LPSTR, PDWORD, LPSTR, PDWORD, PSID_NAME_USE);
WINBASEAPI BOOL WINAPI LookupAccountSidW
(LPCWSTR, PSID, LPWSTR, PDWORD, LPWSTR, PDWORD, PSID_NAME_USE);

#define LookupPrivilegeDisplayName __AW_SUFFIXED__(LookupPrivilegeDisplayName)
WINBASEAPI BOOL WINAPI LookupPrivilegeDisplayNameA
(LPCSTR, LPCSTR, LPSTR, PDWORD, PDWORD);
WINBASEAPI BOOL WINAPI LookupPrivilegeDisplayNameW
(LPCWSTR, LPCWSTR, LPWSTR, PDWORD, PDWORD);

#define LookupPrivilegeName __AW_SUFFIXED__(LookupPrivilegeName)
WINBASEAPI BOOL WINAPI LookupPrivilegeNameA (LPCSTR, PLUID, LPSTR, PDWORD);
WINBASEAPI BOOL WINAPI LookupPrivilegeNameW (LPCWSTR, PLUID, LPWSTR, PDWORD);

#define LookupPrivilegeValue __AW_SUFFIXED__(LookupPrivilegeValue)
WINBASEAPI BOOL WINAPI LookupPrivilegeValueA (LPCSTR, LPCSTR, PLUID);
WINBASEAPI BOOL WINAPI LookupPrivilegeValueW (LPCWSTR, LPCWSTR, PLUID);

#define lstrcat __AW_SUFFIXED__(lstrcat)
WINBASEAPI LPSTR WINAPI lstrcatA (LPSTR, LPCSTR);
WINBASEAPI LPWSTR WINAPI lstrcatW (LPWSTR, LPCWSTR);

#define lstrcmp __AW_SUFFIXED__(lstrcmp)
WINBASEAPI int WINAPI lstrcmpA (LPCSTR, LPCSTR);
WINBASEAPI int WINAPI lstrcmpW (LPCWSTR, LPCWSTR);

#define lstrcmpi __AW_SUFFIXED__(lstrcmpi)
WINBASEAPI int WINAPI lstrcmpiA (LPCSTR, LPCSTR);
WINBASEAPI int WINAPI lstrcmpiW (LPCWSTR, LPCWSTR);

#define lstrcpy __AW_SUFFIXED__(lstrcpy)
WINBASEAPI LPSTR WINAPI lstrcpyA (LPSTR, LPCSTR);
WINBASEAPI LPWSTR WINAPI lstrcpyW (LPWSTR, LPCWSTR);

#define lstrcpyn __AW_SUFFIXED__(lstrcpyn)
WINBASEAPI LPSTR WINAPI lstrcpynA (LPSTR, LPCSTR, int);
WINBASEAPI LPWSTR WINAPI lstrcpynW (LPWSTR, LPCWSTR, int);

#define lstrlen __AW_SUFFIXED__(lstrlen)
WINBASEAPI int WINAPI lstrlenA (LPCSTR);
WINBASEAPI int WINAPI lstrlenW (LPCWSTR);

WINBASEAPI BOOL WINAPI MakeAbsoluteSD
( PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PDWORD, PACL, PDWORD, PACL,
  PDWORD, PSID, PDWORD, PSID, PDWORD
);

#define MakeProcInstance(p, i)  (p)

WINBASEAPI BOOL WINAPI MakeSelfRelativeSD
(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR, PDWORD);
WINBASEAPI VOID WINAPI MapGenericMask (PDWORD, PGENERIC_MAPPING);
WINBASEAPI PVOID WINAPI MapViewOfFile (HANDLE, DWORD, DWORD, DWORD, DWORD);
WINBASEAPI PVOID WINAPI MapViewOfFileEx
(HANDLE, DWORD, DWORD, DWORD, DWORD, PVOID);

#define MoveFile __AW_SUFFIXED__(MoveFile)
WINBASEAPI BOOL WINAPI MoveFileA (LPCSTR, LPCSTR);
WINBASEAPI BOOL WINAPI MoveFileW (LPCWSTR, LPCWSTR);

#define MoveFileEx __AW_SUFFIXED__(MoveFileEx)
WINBASEAPI BOOL WINAPI MoveFileExA (LPCSTR, LPCSTR, DWORD);
WINBASEAPI BOOL WINAPI MoveFileExW (LPCWSTR, LPCWSTR, DWORD);

WINBASEAPI int WINAPI MulDiv (int, int, int);
WINBASEAPI BOOL WINAPI NotifyChangeEventLog (HANDLE, HANDLE);

#define ObjectCloseAuditAlarm __AW_SUFFIXED__(ObjectCloseAuditAlarm)
WINBASEAPI BOOL WINAPI ObjectCloseAuditAlarmA (LPCSTR, PVOID, BOOL);
WINBASEAPI BOOL WINAPI ObjectCloseAuditAlarmW (LPCWSTR, PVOID, BOOL);

#define ObjectDeleteAuditAlarm __AW_SUFFIXED__(ObjectDeleteAuditAlarm)
WINBASEAPI BOOL WINAPI ObjectDeleteAuditAlarmA (LPCSTR, PVOID, BOOL);
WINBASEAPI BOOL WINAPI ObjectDeleteAuditAlarmW (LPCWSTR, PVOID, BOOL);

#define ObjectOpenAuditAlarm __AW_SUFFIXED__(ObjectOpenAuditAlarm)
WINBASEAPI BOOL WINAPI ObjectOpenAuditAlarmA
( LPCSTR, PVOID, LPSTR, LPSTR, PSECURITY_DESCRIPTOR, HANDLE, DWORD, DWORD,
  PPRIVILEGE_SET, BOOL, BOOL, PBOOL
);
WINBASEAPI BOOL WINAPI ObjectOpenAuditAlarmW
( LPCWSTR, PVOID, LPWSTR, LPWSTR, PSECURITY_DESCRIPTOR, HANDLE, DWORD,
  DWORD, PPRIVILEGE_SET, BOOL, BOOL, PBOOL
);

#define ObjectPrivilegeAuditAlarm __AW_SUFFIXED__(ObjectPrivilegeAuditAlarm)
WINBASEAPI BOOL WINAPI ObjectPrivilegeAuditAlarmA
(LPCSTR, PVOID, HANDLE, DWORD, PPRIVILEGE_SET, BOOL);
WINBASEAPI BOOL WINAPI ObjectPrivilegeAuditAlarmW
(LPCWSTR, PVOID, HANDLE, DWORD, PPRIVILEGE_SET, BOOL);

#define OpenBackupEventLog __AW_SUFFIXED__(OpenBackupEventLog)
WINBASEAPI HANDLE WINAPI OpenBackupEventLogA (LPCSTR, LPCSTR);
WINBASEAPI HANDLE WINAPI OpenBackupEventLogW (LPCWSTR, LPCWSTR);

#define OpenEvent __AW_SUFFIXED__(OpenEvent)
WINBASEAPI HANDLE WINAPI OpenEventA (DWORD, BOOL, LPCSTR);
WINBASEAPI HANDLE WINAPI OpenEventW (DWORD, BOOL, LPCWSTR);

#define OpenEventLog __AW_SUFFIXED__(OpenEventLog)
WINBASEAPI HANDLE WINAPI OpenEventLogA (LPCSTR, LPCSTR);
WINBASEAPI HANDLE WINAPI OpenEventLogW (LPCWSTR, LPCWSTR);

WINBASEAPI HFILE WINAPI OpenFile (LPCSTR, LPOFSTRUCT, UINT);

#define OpenFileMapping __AW_SUFFIXED__(OpenFileMapping)
WINBASEAPI HANDLE WINAPI OpenFileMappingA (DWORD, BOOL, LPCSTR);
WINBASEAPI HANDLE WINAPI OpenFileMappingW (DWORD, BOOL, LPCWSTR);

#define OpenMutex __AW_SUFFIXED__(OpenMutex)
WINBASEAPI HANDLE WINAPI OpenMutexA (DWORD, BOOL, LPCSTR);
WINBASEAPI HANDLE WINAPI OpenMutexW (DWORD, BOOL, LPCWSTR);

WINBASEAPI HANDLE WINAPI OpenProcess (DWORD, BOOL, DWORD);
WINBASEAPI BOOL WINAPI OpenProcessToken (HANDLE, DWORD, PHANDLE);

#define OpenSemaphore __AW_SUFFIXED__(OpenSemaphore)
WINBASEAPI HANDLE WINAPI OpenSemaphoreA (DWORD, BOOL, LPCSTR);
WINBASEAPI HANDLE WINAPI OpenSemaphoreW (DWORD, BOOL, LPCWSTR);

WINBASEAPI BOOL WINAPI OpenThreadToken (HANDLE, DWORD, BOOL, PHANDLE);

/* OpenWaitableTimer: previously missing UNICODE vs. ANSI define */
#define OpenWaitableTimer __AW_SUFFIXED__(OpenWaitableTimer)
WINBASEAPI HANDLE WINAPI OpenWaitableTimerA (DWORD, BOOL, LPCSTR);
WINBASEAPI HANDLE WINAPI OpenWaitableTimerW (DWORD, BOOL, LPCWSTR);

#define OutputDebugString __AW_SUFFIXED__(OutputDebugString)
WINBASEAPI void WINAPI OutputDebugStringA (LPCSTR);
WINBASEAPI void WINAPI OutputDebugStringW (LPCWSTR);

WINBASEAPI BOOL WINAPI PeekNamedPipe
(HANDLE, PVOID, DWORD, PDWORD, PDWORD, PDWORD);
WINBASEAPI BOOL WINAPI PostQueuedCompletionStatus
(HANDLE, DWORD, ULONG_PTR, LPOVERLAPPED);
WINBASEAPI DWORD WINAPI PrepareTape (HANDLE, DWORD, BOOL);
WINBASEAPI BOOL WINAPI PrivilegeCheck (HANDLE, PPRIVILEGE_SET, PBOOL);

#define PrivilegedServiceAuditAlarm __AW_SUFFIXED__(PrivilegedServiceAuditAlarm)
WINBASEAPI BOOL WINAPI PrivilegedServiceAuditAlarmA
(LPCSTR, LPCSTR, HANDLE, PPRIVILEGE_SET, BOOL);
WINBASEAPI BOOL WINAPI PrivilegedServiceAuditAlarmW
(LPCWSTR, LPCWSTR, HANDLE, PPRIVILEGE_SET, BOOL);

WINBASEAPI BOOL WINAPI PulseEvent (HANDLE);
WINBASEAPI BOOL WINAPI PurgeComm (HANDLE, DWORD);

#define QueryDosDevice __AW_SUFFIXED__(QueryDosDevice)
WINBASEAPI DWORD WINAPI QueryDosDeviceA (LPCSTR, LPSTR, DWORD);
WINBASEAPI DWORD WINAPI QueryDosDeviceW (LPCWSTR, LPWSTR, DWORD);
WINBASEAPI BOOL WINAPI QueryPerformanceCounter (PLARGE_INTEGER);
WINBASEAPI BOOL WINAPI QueryPerformanceFrequency (PLARGE_INTEGER);
WINBASEAPI DWORD WINAPI QueueUserAPC (PAPCFUNC, HANDLE, ULONG_PTR);

WINBASEAPI void WINAPI RaiseException (DWORD, DWORD, DWORD, const DWORD *);
WINBASEAPI BOOL WINAPI ReadDirectoryChangesW
( HANDLE, PVOID, DWORD, BOOL, DWORD, PDWORD, LPOVERLAPPED,
  LPOVERLAPPED_COMPLETION_ROUTINE
);

#define ReadEventLog __AW_SUFFIXED__(ReadEventLog)
WINBASEAPI BOOL WINAPI ReadEventLogA
(HANDLE, DWORD, DWORD, PVOID, DWORD, DWORD *, DWORD *);
WINBASEAPI BOOL WINAPI ReadEventLogW
(HANDLE, DWORD, DWORD, PVOID, DWORD, DWORD *, DWORD *);

WINBASEAPI BOOL WINAPI ReadFile (HANDLE, PVOID, DWORD, PDWORD, LPOVERLAPPED);
WINBASEAPI BOOL WINAPI ReadFileEx
(HANDLE, PVOID, DWORD, LPOVERLAPPED, LPOVERLAPPED_COMPLETION_ROUTINE);
WINBASEAPI BOOL WINAPI ReadFileScatter
(HANDLE, FILE_SEGMENT_ELEMENT *, DWORD, LPDWORD, LPOVERLAPPED);
WINBASEAPI BOOL WINAPI ReadProcessMemory (HANDLE, PCVOID, PVOID, DWORD, PDWORD);

#define RegisterEventSource __AW_SUFFIXED__(RegisterEventSource)
WINBASEAPI HANDLE WINAPI RegisterEventSourceA (LPCSTR, LPCSTR);
WINBASEAPI HANDLE WINAPI RegisterEventSourceW (LPCWSTR, LPCWSTR);

WINBASEAPI BOOL WINAPI ReleaseMutex (HANDLE);
WINBASEAPI BOOL WINAPI ReleaseSemaphore (HANDLE, LONG, LPLONG);

#define RemoveDirectory __AW_SUFFIXED__(RemoveDirectory)
WINBASEAPI BOOL WINAPI RemoveDirectoryA (LPCSTR);
WINBASEAPI BOOL WINAPI RemoveDirectoryW (LPCWSTR);

#define ReportEvent __AW_SUFFIXED__(ReportEvent)
WINBASEAPI BOOL WINAPI ReportEventA
(HANDLE, WORD, WORD, DWORD, PSID, WORD, DWORD, LPCSTR *, PVOID);
WINBASEAPI BOOL WINAPI ReportEventW
(HANDLE, WORD, WORD, DWORD, PSID, WORD, DWORD, LPCWSTR *, PVOID);

#ifdef _WIN32_WCE
extern BOOL ResetEvent (HANDLE);
#else
WINBASEAPI BOOL WINAPI ResetEvent (HANDLE);
#endif

WINBASEAPI UINT WINAPI ResetWriteWatch (LPVOID, SIZE_T);
WINBASEAPI DWORD WINAPI ResumeThread (HANDLE);
WINBASEAPI BOOL WINAPI RevertToSelf (void);

#define SearchPath __AW_SUFFIXED__(SearchPath)
WINBASEAPI DWORD WINAPI SearchPathA
(LPCSTR, LPCSTR, LPCSTR, DWORD, LPSTR, LPSTR *);
WINBASEAPI DWORD WINAPI SearchPathW
(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPWSTR, LPWSTR *);

WINBASEAPI BOOL WINAPI SetAclInformation
(PACL, PVOID, DWORD, ACL_INFORMATION_CLASS);
WINBASEAPI BOOL WINAPI SetCommBreak (HANDLE);
WINBASEAPI BOOL WINAPI SetCommConfig (HANDLE, LPCOMMCONFIG, DWORD);
WINBASEAPI BOOL WINAPI SetCommMask (HANDLE, DWORD);
WINBASEAPI BOOL WINAPI SetCommState (HANDLE, LPDCB);
WINBASEAPI BOOL WINAPI SetCommTimeouts (HANDLE, LPCOMMTIMEOUTS);

#define SetComputerName __AW_SUFFIXED__(SetComputerName)
WINBASEAPI BOOL WINAPI SetComputerNameA (LPCSTR);
WINBASEAPI BOOL WINAPI SetComputerNameW (LPCWSTR);

#define SetCurrentDirectory __AW_SUFFIXED__(SetCurrentDirectory)
WINBASEAPI BOOL WINAPI SetCurrentDirectoryA (LPCSTR);
WINBASEAPI BOOL WINAPI SetCurrentDirectoryW (LPCWSTR);

#define SetDefaultCommConfig __AW_SUFFIXED__(SetDefaultCommConfig)
WINBASEAPI BOOL WINAPI SetDefaultCommConfigA (LPCSTR, LPCOMMCONFIG, DWORD);
WINBASEAPI BOOL WINAPI SetDefaultCommConfigW (LPCWSTR, LPCOMMCONFIG, DWORD);

WINBASEAPI BOOL WINAPI SetEndOfFile (HANDLE);

#define SetEnvironmentVariable __AW_SUFFIXED__(SetEnvironmentVariable)
WINBASEAPI BOOL WINAPI SetEnvironmentVariableA (LPCSTR, LPCSTR);
WINBASEAPI BOOL WINAPI SetEnvironmentVariableW (LPCWSTR, LPCWSTR);

WINBASEAPI UINT WINAPI SetErrorMode (UINT);

#ifdef _WIN32_WCE
extern BOOL SetEvent (HANDLE);
#else
WINBASEAPI BOOL WINAPI SetEvent (HANDLE);
#endif

WINBASEAPI VOID WINAPI SetFileApisToANSI (void);
WINBASEAPI VOID WINAPI SetFileApisToOEM (void);

#define SetFileAttributes __AW_SUFFIXED__(SetFileAttributes)
WINBASEAPI BOOL WINAPI SetFileAttributesA (LPCSTR, DWORD);
WINBASEAPI BOOL WINAPI SetFileAttributesW (LPCWSTR, DWORD);

WINBASEAPI DWORD WINAPI SetFilePointer (HANDLE, LONG, PLONG, DWORD);
WINBASEAPI BOOL WINAPI SetFilePointerEx
(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD);

#define SetFileSecurity __AW_SUFFIXED__(SetFileSecurity)
WINBASEAPI BOOL WINAPI SetFileSecurityA
(LPCSTR, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
WINBASEAPI BOOL WINAPI SetFileSecurityW
(LPCWSTR, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);

WINBASEAPI BOOL WINAPI SetFileTime
(HANDLE, const FILETIME *, const FILETIME *, const FILETIME *);

WINBASEAPI UINT WINAPI SetHandleCount (UINT);
WINBASEAPI BOOL WINAPI SetHandleInformation (HANDLE, DWORD, DWORD);
WINBASEAPI BOOL WINAPI SetKernelObjectSecurity
(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
WINBASEAPI void WINAPI SetLastError (DWORD);
WINBASEAPI void WINAPI SetLastErrorEx (DWORD, DWORD);
WINBASEAPI BOOL WINAPI SetLocalTime (const SYSTEMTIME *);
WINBASEAPI BOOL WINAPI SetMailslotInfo (HANDLE, DWORD);
WINBASEAPI BOOL WINAPI SetNamedPipeHandleState (HANDLE, PDWORD, PDWORD, PDWORD);
WINBASEAPI BOOL WINAPI SetPriorityClass (HANDLE, DWORD);
WINBASEAPI BOOL WINAPI SetPrivateObjectSecurity
( SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR *,
  PGENERIC_MAPPING, HANDLE
);
WINBASEAPI BOOL WINAPI SetProcessAffinityMask (HANDLE, DWORD);
WINBASEAPI BOOL WINAPI SetProcessPriorityBoost (HANDLE, BOOL);
WINBASEAPI BOOL WINAPI SetProcessShutdownParameters (DWORD, DWORD);
WINBASEAPI BOOL WINAPI SetProcessWorkingSetSize (HANDLE, SIZE_T, SIZE_T);
WINBASEAPI BOOL WINAPI SetSecurityDescriptorControl
( PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR_CONTROL, SECURITY_DESCRIPTOR_CONTROL
);
WINBASEAPI BOOL WINAPI SetSecurityDescriptorDacl
(PSECURITY_DESCRIPTOR, BOOL, PACL, BOOL);
WINBASEAPI BOOL WINAPI SetSecurityDescriptorGroup
(PSECURITY_DESCRIPTOR, PSID, BOOL);
WINBASEAPI BOOL WINAPI SetSecurityDescriptorOwner
(PSECURITY_DESCRIPTOR, PSID, BOOL);
WINBASEAPI BOOL WINAPI SetSecurityDescriptorSacl
(PSECURITY_DESCRIPTOR, BOOL, PACL, BOOL);
WINBASEAPI BOOL WINAPI SetStdHandle (DWORD, HANDLE);

#define SetSwapAreaSize(w)  (w)

WINBASEAPI BOOL WINAPI SetSystemPowerState (BOOL, BOOL);
WINBASEAPI BOOL WINAPI SetSystemTime (const SYSTEMTIME *);
WINBASEAPI BOOL WINAPI SetSystemTimeAdjustment (DWORD, BOOL);
WINBASEAPI DWORD WINAPI SetTapeParameters (HANDLE, DWORD, PVOID);
WINBASEAPI DWORD WINAPI SetTapePosition
(HANDLE, DWORD, DWORD, DWORD, DWORD, BOOL);
WINBASEAPI DWORD WINAPI SetThreadAffinityMask (HANDLE, DWORD);
WINBASEAPI BOOL WINAPI SetThreadContext (HANDLE, const CONTEXT *);

WINBASEAPI DWORD WINAPI SetThreadIdealProcessor (HANDLE, DWORD);
WINBASEAPI BOOL WINAPI SetThreadPriority (HANDLE, int);
WINBASEAPI BOOL WINAPI SetThreadPriorityBoost (HANDLE, BOOL);
WINBASEAPI BOOL WINAPI SetThreadToken (PHANDLE, HANDLE);
WINBASEAPI BOOL WINAPI SetTimeZoneInformation (const TIME_ZONE_INFORMATION *);
WINBASEAPI BOOL WINAPI SetTokenInformation
(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, DWORD);
WINBASEAPI LPTOP_LEVEL_EXCEPTION_FILTER WINAPI SetUnhandledExceptionFilter
(LPTOP_LEVEL_EXCEPTION_FILTER);
WINBASEAPI BOOL WINAPI SetupComm (HANDLE, DWORD, DWORD);

#define SetVolumeLabel __AW_SUFFIXED__(SetVolumeLabel)
WINBASEAPI BOOL WINAPI SetVolumeLabelA (LPCSTR, LPCSTR);
WINBASEAPI BOOL WINAPI SetVolumeLabelW (LPCWSTR, LPCWSTR);

WINBASEAPI BOOL WINAPI SetWaitableTimer
(HANDLE, const LARGE_INTEGER *, LONG, PTIMERAPCROUTINE, PVOID, BOOL);
WINBASEAPI DWORD WINAPI SignalObjectAndWait (HANDLE, HANDLE, DWORD, BOOL);
WINBASEAPI DWORD WINAPI SizeofResource (HINSTANCE, HRSRC);
WINBASEAPI void WINAPI Sleep (DWORD);
WINBASEAPI DWORD WINAPI SleepEx (DWORD, BOOL);
WINBASEAPI DWORD WINAPI SuspendThread (HANDLE);
WINBASEAPI void WINAPI SwitchToFiber (PVOID);
WINBASEAPI BOOL WINAPI SwitchToThread (void);
WINBASEAPI BOOL WINAPI SystemTimeToFileTime (const SYSTEMTIME *, LPFILETIME);
WINBASEAPI BOOL WINAPI SystemTimeToTzSpecificLocalTime
(LPTIME_ZONE_INFORMATION, LPSYSTEMTIME, LPSYSTEMTIME);

WINBASEAPI BOOL WINAPI TerminateProcess (HANDLE, UINT);
WINBASEAPI BOOL WINAPI TerminateThread (HANDLE, DWORD);
WINBASEAPI DWORD WINAPI TlsAlloc (VOID);
WINBASEAPI BOOL WINAPI TlsFree (DWORD);
WINBASEAPI PVOID WINAPI TlsGetValue (DWORD);
WINBASEAPI BOOL WINAPI TlsSetValue (DWORD, PVOID);
WINBASEAPI BOOL WINAPI TransactNamedPipe
(HANDLE, PVOID, DWORD, PVOID, DWORD, PDWORD, LPOVERLAPPED);
WINBASEAPI BOOL WINAPI TransmitCommChar (HANDLE, char);
WINBASEAPI BOOL WINAPI TryEnterCriticalSection (LPCRITICAL_SECTION);
WINBASEAPI LONG WINAPI UnhandledExceptionFilter (LPEXCEPTION_POINTERS);
WINBASEAPI BOOL WINAPI UnlockFile (HANDLE, DWORD, DWORD, DWORD, DWORD);
WINBASEAPI BOOL WINAPI UnlockFileEx (HANDLE, DWORD, DWORD, DWORD, LPOVERLAPPED);

#define UnlockResource(h)  (h)
#define UnlockSegment(w)   GlobalUnfix((HANDLE)(w)) /* Obsolete: Has no effect. */

WINBASEAPI BOOL WINAPI UnmapViewOfFile (LPCVOID);

#define UpdateResource __AW_SUFFIXED__(UpdateResource)
WINBASEAPI BOOL WINAPI UpdateResourceA
(HANDLE, LPCSTR, LPCSTR, WORD, PVOID, DWORD);
WINBASEAPI BOOL WINAPI UpdateResourceW
(HANDLE, LPCWSTR, LPCWSTR, WORD, PVOID, DWORD);

#define VerifyVersionInfo __AW_SUFFIXED__(VerifyVersionInfo)
WINBASEAPI BOOL WINAPI VerifyVersionInfoA
(LPOSVERSIONINFOEXA, DWORD, DWORDLONG);
WINBASEAPI BOOL WINAPI VerifyVersionInfoW
(LPOSVERSIONINFOEXW, DWORD, DWORDLONG);

WINBASEAPI PVOID WINAPI VirtualAlloc (PVOID, DWORD, DWORD, DWORD);
WINBASEAPI PVOID WINAPI VirtualAllocEx (HANDLE, PVOID, DWORD, DWORD, DWORD);
WINBASEAPI BOOL WINAPI VirtualFree (PVOID, DWORD, DWORD);
WINBASEAPI BOOL WINAPI VirtualFreeEx (HANDLE, PVOID, DWORD, DWORD);
WINBASEAPI BOOL WINAPI VirtualLock (PVOID, DWORD);
WINBASEAPI BOOL WINAPI VirtualProtect (PVOID, DWORD, DWORD, PDWORD);
WINBASEAPI BOOL WINAPI VirtualProtectEx (HANDLE, PVOID, DWORD, DWORD, PDWORD);
WINBASEAPI DWORD WINAPI VirtualQuery (LPCVOID, PMEMORY_BASIC_INFORMATION, DWORD);
WINBASEAPI DWORD WINAPI VirtualQueryEx
(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, DWORD);
WINBASEAPI BOOL WINAPI VirtualUnlock (PVOID, DWORD);
WINBASEAPI BOOL WINAPI WaitCommEvent (HANDLE, PDWORD, LPOVERLAPPED);
WINBASEAPI BOOL WINAPI WaitForDebugEvent (LPDEBUG_EVENT, DWORD);
WINBASEAPI DWORD WINAPI WaitForMultipleObjects
(DWORD, const HANDLE *, BOOL, DWORD);
WINBASEAPI DWORD WINAPI WaitForMultipleObjectsEx
(DWORD, const HANDLE *, BOOL, DWORD, BOOL);
WINBASEAPI DWORD WINAPI WaitForSingleObject (HANDLE, DWORD);
WINBASEAPI DWORD WINAPI WaitForSingleObjectEx (HANDLE, DWORD, BOOL);

#define WaitNamedPipe __AW_SUFFIXED__(WaitNamedPipe)
WINBASEAPI BOOL WINAPI WaitNamedPipeA (LPCSTR, DWORD);
WINBASEAPI BOOL WINAPI WaitNamedPipeW (LPCWSTR, DWORD);

WINBASEAPI BOOL WINAPI WinLoadTrustProvider (GUID *);
WINBASEAPI BOOL WINAPI WriteFile (HANDLE, PCVOID, DWORD, PDWORD, LPOVERLAPPED);
WINBASEAPI BOOL WINAPI WriteFileEx
(HANDLE, PCVOID, DWORD, LPOVERLAPPED, LPOVERLAPPED_COMPLETION_ROUTINE);
WINBASEAPI BOOL WINAPI WriteFileGather
(HANDLE, FILE_SEGMENT_ELEMENT *, DWORD, LPDWORD, LPOVERLAPPED);

#define WritePrivateProfileSection __AW_SUFFIXED__(WritePrivateProfileSection)
WINBASEAPI BOOL WINAPI WritePrivateProfileSectionA (LPCSTR, LPCSTR, LPCSTR);
WINBASEAPI BOOL WINAPI WritePrivateProfileSectionW (LPCWSTR, LPCWSTR, LPCWSTR);

#define WritePrivateProfileString __AW_SUFFIXED__(WritePrivateProfileString)
WINBASEAPI BOOL WINAPI WritePrivateProfileStringA
(LPCSTR, LPCSTR, LPCSTR, LPCSTR);
WINBASEAPI BOOL WINAPI WritePrivateProfileStringW
(LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR);

#define WritePrivateProfileStruct __AW_SUFFIXED__(WritePrivateProfileStruct)
WINBASEAPI BOOL WINAPI WritePrivateProfileStructA
(LPCSTR, LPCSTR, LPVOID, UINT, LPCSTR);
WINBASEAPI BOOL WINAPI WritePrivateProfileStructW
(LPCWSTR, LPCWSTR, LPVOID, UINT, LPCWSTR);

WINBASEAPI BOOL WINAPI WriteProcessMemory
(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);

#define WriteProfileSection __AW_SUFFIXED__(WriteProfileSection)
WINBASEAPI BOOL WINAPI WriteProfileSectionA (LPCSTR, LPCSTR);
WINBASEAPI BOOL WINAPI WriteProfileSectionW (LPCWSTR, LPCWSTR);

#define WriteProfileString __AW_SUFFIXED__(WriteProfileString)
WINBASEAPI BOOL WINAPI WriteProfileStringA (LPCSTR, LPCSTR, LPCSTR);
WINBASEAPI BOOL WINAPI WriteProfileStringW (LPCWSTR, LPCWSTR, LPCWSTR);

WINBASEAPI DWORD WINAPI WriteTapemark (HANDLE, DWORD, DWORD, BOOL);

#define Yield()

#if _WIN32_WINNT >= _WIN32_WINNT_NT4
/* Features available on all Win9x versions, but not introduced to the
 * WinNT platform series until the release of Windows-NT4.
 */
WINBASEAPI BOOL WINAPI ConvertFiberToThread (void);
WINBASEAPI LPVOID WINAPI CreateFiberEx
(SIZE_T, SIZE_T, DWORD, LPFIBER_START_ROUTINE, LPVOID);
#endif	/* Win9x, but not WinNT until NT4 */

#if _WIN32_WINDOWS >= _WIN32_WINDOWS_98 || _WIN32_WINNT >= _WIN32_WINNT_WIN2K
/* New features, introduced to Win9x from Win98 onwards, and also to the WinNT
 * platform series, from Win2K onwards.
 */
typedef DWORD EXECUTION_STATE;

#define GetLongPathName __AW_SUFFIXED__(GetLongPathName)
WINBASEAPI DWORD WINAPI GetLongPathNameA (LPCSTR, LPSTR, DWORD);
WINBASEAPI DWORD WINAPI GetLongPathNameW (LPCWSTR, LPWSTR, DWORD);

WINBASEAPI EXECUTION_STATE WINAPI SetThreadExecutionState (EXECUTION_STATE);

#if _WIN32_WINDOWS >= _WIN32_WINDOWS_ME || _WIN32_WINNT >= _WIN32_WINNT_WIN2K
/* The OpenThread() API is supported in WinNT versions, from Win2K onwards,
 * but was introduced to the Win9X series only in the Millennium Edition.
 */
WINBASEAPI HANDLE WINAPI OpenThread (DWORD, BOOL, DWORD);
#endif	/* WinNT from Win2K onwards, and WinME */

#if _WIN32_WINNT >= _WIN32_WINNT_WIN2K
/* Additional new features introduced in Win2K, but not available in Win9x.
 */
typedef struct _MEMORYSTATUSEX
{ DWORD 			dwLength;
  DWORD 			dwMemoryLoad;
  DWORDLONG			ullTotalPhys;
  DWORDLONG			ullAvailPhys;
  DWORDLONG			ullTotalPageFile;
  DWORDLONG			ullAvailPageFile;
  DWORDLONG			ullTotalVirtual;
  DWORDLONG			ullAvailVirtual;
  DWORDLONG			ullAvailExtendedVirtual;
} MEMORYSTATUSEX, *LPMEMORYSTATUSEX;

typedef enum _COMPUTER_NAME_FORMAT
{ ComputerNameNetBIOS,
  ComputerNameDnsHostname,
  ComputerNameDnsDomain,
  ComputerNameDnsFullyQualified,
  ComputerNamePhysicalNetBIOS,
  ComputerNamePhysicalDnsHostname,
  ComputerNamePhysicalDnsDomain,
  ComputerNamePhysicalDnsFullyQualified,
  ComputerNameMax
} COMPUTER_NAME_FORMAT;

typedef void (CALLBACK *WAITORTIMERCALLBACK)(PVOID, BOOLEAN);

WINBASEAPI BOOL WINAPI AddAccessAllowedAceEx (PACL, DWORD, DWORD, DWORD, PSID);
WINBASEAPI BOOL WINAPI AddAccessDeniedAceEx (PACL, DWORD, DWORD, DWORD, PSID);
WINBASEAPI PVOID WINAPI AddVectoredExceptionHandler
(ULONG, PVECTORED_EXCEPTION_HANDLER);

WINBASEAPI BOOL WINAPI ChangeTimerQueueTimer (HANDLE, HANDLE, ULONG, ULONG);
WINBASEAPI BOOL WINAPI CheckTokenMembership (HANDLE, PSID, PBOOL);

#define CreateHardLink __AW_SUFFIXED__(CreateHardLink)
WINBASEAPI BOOL WINAPI CreateHardLinkA (LPCSTR, LPCSTR, LPSECURITY_ATTRIBUTES);
WINBASEAPI BOOL WINAPI CreateHardLinkW
(LPCWSTR, LPCWSTR, LPSECURITY_ATTRIBUTES);

#define CreateJobObject __AW_SUFFIXED__(CreateJobObject)
WINBASEAPI HANDLE WINAPI CreateJobObjectA (LPSECURITY_ATTRIBUTES, LPCSTR);
WINBASEAPI HANDLE WINAPI CreateJobObjectW (LPSECURITY_ATTRIBUTES, LPCWSTR);

WINBASEAPI BOOL WINAPI TerminateJobObject (HANDLE, UINT);
WINBASEAPI BOOL WINAPI AssignProcessToJobObject (HANDLE, HANDLE);

WINBASEAPI BOOL WINAPI SetInformationJobObject
(HANDLE, JOBOBJECTINFOCLASS, LPVOID, DWORD);
WINBASEAPI BOOL WINAPI QueryInformationJobObject
(HANDLE, JOBOBJECTINFOCLASS, LPVOID, DWORD, LPDWORD);

WINBASEAPI BOOL WINAPI CreateProcessWithLogonW
( LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID,
  LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION
);
#define LOGON_WITH_PROFILE		0x00000001
#define LOGON_NETCREDENTIALS_ONLY	0x00000002

WINBASEAPI BOOL WINAPI CreateRestrictedToken
( HANDLE, DWORD, DWORD, PSID_AND_ATTRIBUTES, DWORD, PLUID_AND_ATTRIBUTES,
  DWORD, PSID_AND_ATTRIBUTES, PHANDLE
);
#define DISABLE_MAX_PRIVILEGE	1
#define SANDBOX_INERT		2
#define LUA_TOKEN		4
#define WRITE_RESTRICTED	8

WINBASEAPI HANDLE WINAPI CreateTimerQueue (void);
WINBASEAPI BOOL WINAPI CreateTimerQueueTimer
(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);

WINBASEAPI BOOL WINAPI DeleteTimerQueue (HANDLE);
WINBASEAPI BOOL WINAPI DeleteTimerQueueEx (HANDLE, HANDLE);
WINBASEAPI BOOL WINAPI DeleteTimerQueueTimer (HANDLE, HANDLE, HANDLE);

#define DeleteVolumeMountPoint __AW_SUFFIXED__(DeleteVolumeMountPoint)
WINBASEAPI BOOL WINAPI DeleteVolumeMountPointA (LPCSTR);
WINBASEAPI BOOL WINAPI DeleteVolumeMountPointW (LPCWSTR);

#define DnsHostnameToComputerName __AW_SUFFIXED__(DnsHostnameToComputerName)
WINBASEAPI BOOL WINAPI DnsHostnameToComputerNameA (LPCSTR, LPSTR, LPDWORD);
WINBASEAPI BOOL WINAPI DnsHostnameToComputerNameW (LPCWSTR, LPWSTR, LPDWORD);

#define FindFirstVolume __AW_SUFFIXED__(FindFirstVolume)
WINBASEAPI HANDLE WINAPI FindFirstVolumeA (LPCSTR, DWORD);
WINBASEAPI HANDLE WINAPI FindFirstVolumeW (LPCWSTR, DWORD);

#define FindFirstVolumeMountPoint __AW_SUFFIXED__(FindFirstVolumeMountPoint)
WINBASEAPI HANDLE WINAPI FindFirstVolumeMountPointA (LPSTR, LPSTR, DWORD);
WINBASEAPI HANDLE WINAPI FindFirstVolumeMountPointW (LPWSTR, LPWSTR, DWORD);

#define FindNextVolume __AW_SUFFIXED__(FindNextVolume)
WINBASEAPI BOOL WINAPI FindNextVolumeA (HANDLE, LPCSTR, DWORD);
WINBASEAPI BOOL WINAPI FindNextVolumeW (HANDLE, LPWSTR, DWORD);

#define FindNextVolumeMountPoint __AW_SUFFIXED__(FindNextVolumeMountPoint)
WINBASEAPI BOOL WINAPI FindNextVolumeMountPointA (HANDLE, LPSTR, DWORD);
WINBASEAPI BOOL WINAPI FindNextVolumeMountPointW (HANDLE, LPWSTR, DWORD);

WINBASEAPI BOOL WINAPI FindVolumeClose (HANDLE);
WINBASEAPI BOOL WINAPI FindVolumeMountPointClose (HANDLE);

#define GetComputerNameEx __AW_SUFFIXED__(GetComputerNameEx)
WINBASEAPI BOOL WINAPI GetComputerNameExA
(COMPUTER_NAME_FORMAT, LPSTR, LPDWORD);
WINBASEAPI BOOL WINAPI GetComputerNameExW
(COMPUTER_NAME_FORMAT, LPWSTR, LPDWORD);

WINBASEAPI BOOL WINAPI GetFileSizeEx (HANDLE, PLARGE_INTEGER);
WINBASEAPI BOOL WINAPI GetProcessIoCounters (HANDLE, PIO_COUNTERS);

#define GetSystemWindowsDirectory __AW_SUFFIXED__(GetSystemWindowsDirectory)
WINBASEAPI UINT WINAPI GetSystemWindowsDirectoryA (LPSTR, UINT);
WINBASEAPI UINT WINAPI GetSystemWindowsDirectoryW (LPWSTR, UINT);
#define \
GetVolumeNameForVolumeMountPoint __AW_SUFFIXED__(GetVolumeNameForVolumeMountPoint)
WINBASEAPI BOOL WINAPI GetVolumeNameForVolumeMountPointA (LPCSTR, LPSTR, DWORD);
WINBASEAPI BOOL WINAPI GetVolumeNameForVolumeMountPointW
(LPCWSTR, LPWSTR, DWORD);

#define GetVolumePathName __AW_SUFFIXED__(GetVolumePathName)
WINBASEAPI BOOL WINAPI GetVolumePathNameA (LPCSTR, LPSTR, DWORD);
WINBASEAPI BOOL WINAPI GetVolumePathNameW (LPCWSTR, LPWSTR, DWORD);

WINBASEAPI BOOL WINAPI GlobalMemoryStatusEx (LPMEMORYSTATUSEX);

WINBASEAPI BOOL WINAPI IsTokenRestricted (HANDLE);

#define MoveFileWithProgress __AW_SUFFIXED__(MoveFileWithProgress)
WINBASEAPI BOOL WINAPI MoveFileWithProgressA
(LPCSTR, LPCSTR, LPPROGRESS_ROUTINE, LPVOID, DWORD);
WINBASEAPI BOOL WINAPI MoveFileWithProgressW
(LPCWSTR, LPCWSTR, LPPROGRESS_ROUTINE, LPVOID, DWORD);

WINBASEAPI BOOL WINAPI ProcessIdToSessionId (DWORD, DWORD *);

WINBASEAPI BOOL WINAPI QueueUserWorkItem (LPTHREAD_START_ROUTINE, PVOID, ULONG);

WINBASEAPI BOOL WINAPI RegisterWaitForSingleObject
(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, ULONG, ULONG);
WINBASEAPI HANDLE WINAPI RegisterWaitForSingleObjectEx
(HANDLE, WAITORTIMERCALLBACK, PVOID, ULONG, ULONG);
WINBASEAPI ULONG WINAPI RemoveVectoredExceptionHandler (PVOID);

#define ReplaceFile __AW_SUFFIXED__(ReplaceFile)
WINBASEAPI BOOL WINAPI ReplaceFileA
(LPCSTR, LPCSTR, LPCSTR, DWORD, LPVOID, LPVOID);
WINBASEAPI BOOL WINAPI ReplaceFileW
(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPVOID, LPVOID);

/* SetComputerNameEx: previously missing UNICODE vs. ANSI define */
#define SetComputerNameEx __AW_SUFFIXED__(SetComputerNameEx)
WINBASEAPI BOOL WINAPI SetComputerNameExA (COMPUTER_NAME_FORMAT, LPCSTR);
WINBASEAPI BOOL WINAPI SetComputerNameExW (COMPUTER_NAME_FORMAT, LPCWSTR);

#define SetVolumeMountPoint __AW_SUFFIXED__(SetVolumeMountPoint)
WINBASEAPI BOOL WINAPI SetVolumeMountPointA (LPCSTR, LPCSTR);
WINBASEAPI BOOL WINAPI SetVolumeMountPointW (LPCWSTR, LPCWSTR);

WINBASEAPI BOOL WINAPI UnregisterWait (HANDLE);
WINBASEAPI BOOL WINAPI UnregisterWaitEx (HANDLE, HANDLE);

WINBASEAPI BOOL WINAPI AllocateUserPhysicalPages
(HANDLE, PULONG_PTR, PULONG_PTR);

WINBASEAPI BOOL WINAPI FreeUserPhysicalPages (HANDLE, PULONG_PTR, PULONG_PTR);

WINBASEAPI BOOL WINAPI MapUserPhysicalPages (PVOID, ULONG_PTR, PULONG_PTR);
WINBASEAPI BOOL WINAPI MapUserPhysicalPagesScatter
(PVOID *, ULONG_PTR, PULONG_PTR);

#if _WIN32_WINNT >= _WIN32_WINNT_WINXP
/* New features, implemented for WinXP; not available in Win9x.
 */
typedef struct tagACTCTXA
{ ULONG 			cbSize;
  DWORD 			dwFlags;
  LPCSTR lpSource;
  USHORT wProcessorArchitecture;
  LANGID wLangId;
  LPCSTR lpAssemblyDirectory;
  LPCSTR lpResourceName;
  LPCSTR lpApplicationName;
  HMODULE hModule;
} ACTCTXA, *PACTCTXA;

typedef struct tagACTCTXW
{ ULONG 			cbSize;
  DWORD 			dwFlags;
  LPCWSTR lpSource;
  USHORT wProcessorArchitecture;
  LANGID wLangId;
  LPCWSTR lpAssemblyDirectory;
  LPCWSTR lpResourceName;
  LPCWSTR lpApplicationName;
  HMODULE hModule;
} ACTCTXW, *PACTCTXW;

typedef const ACTCTXA *PCACTCTXA;
typedef const ACTCTXW *PCACTCTXW;

typedef __AW_ALIAS__(ACTCTX), *PACTCTX;
typedef __AW_ALIAS__(PCACTCTX);

typedef struct tagACTCTX_SECTION_KEYED_DATA
{ ULONG 			cbSize;
  ULONG 			ulDataFormatVersion;
  PVOID 			lpData;
  ULONG 			ulLength;
  PVOID 			lpSectionGlobalData;
  ULONG 			ulSectionGlobalDataLength;
  PVOID 			lpSectionBase;
  ULONG 			ulSectionTotalLength;
  HANDLE hActCtx;
  HANDLE ulAssemblyRosterIndex;
} ACTCTX_SECTION_KEYED_DATA, *PACTCTX_SECTION_KEYED_DATA;

typedef const ACTCTX_SECTION_KEYED_DATA *PCACTCTX_SECTION_KEYED_DATA;

typedef enum
{ LowMemoryResourceNotification,
  HighMemoryResourceNotification
} MEMORY_RESOURCE_NOTIFICATION_TYPE;

WINBASEAPI BOOL WINAPI ActivateActCtx (HANDLE, ULONG_PTR *);
WINBASEAPI void WINAPI AddRefActCtx (HANDLE);

#define CheckNameLegalDOS8Dot3 __AW_SUFFIXED__(CheckNameLegalDOS8Dot3)
WINBASEAPI BOOL WINAPI CheckNameLegalDOS8Dot3A
(LPCSTR, LPSTR, DWORD, PBOOL, PBOOL);
WINBASEAPI BOOL WINAPI CheckNameLegalDOS8Dot3W
(LPCWSTR, LPSTR, DWORD, PBOOL, PBOOL);

WINBASEAPI BOOL WINAPI CheckRemoteDebuggerPresent (HANDLE, PBOOL);

#define CreateActCtx __AW_SUFFIXED__(CreateActCtx)
WINBASEAPI HANDLE WINAPI CreateActCtxA (PCACTCTXA);
WINBASEAPI HANDLE WINAPI CreateActCtxW (PCACTCTXW);

WINBASEAPI HANDLE WINAPI CreateMemoryResourceNotification
(MEMORY_RESOURCE_NOTIFICATION_TYPE);

WINBASEAPI BOOL WINAPI DeactivateActCtx (DWORD, ULONG_PTR);
WINBASEAPI BOOL WINAPI DebugActiveProcessStop (DWORD);
WINBASEAPI BOOL WINAPI DebugBreakProcess (HANDLE);
WINBASEAPI BOOL WINAPI DebugSetProcessKillOnExit (BOOL);

WINBASEAPI BOOL WINAPI FindActCtxSectionGuid
(DWORD, const GUID *, ULONG, const GUID *, PACTCTX_SECTION_KEYED_DATA);

#define FindActCtxSectionString __AW_SUFFIXED__(FindActCtxSectionString)
WINBASEAPI BOOL WINAPI FindActCtxSectionStringA
(DWORD, const GUID *, ULONG, LPCSTR, PACTCTX_SECTION_KEYED_DATA);
WINBASEAPI BOOL WINAPI FindActCtxSectionStringW
(DWORD, const GUID *, ULONG, LPCWSTR, PACTCTX_SECTION_KEYED_DATA);

WINBASEAPI BOOL WINAPI GetCurrentActCtx (HANDLE *);

#define GetModuleHandleEx __AW_SUFFIXED__(GetModuleHandleEx)
WINBASEAPI BOOL WINAPI GetModuleHandleExA (DWORD, LPCSTR, HMODULE *);
WINBASEAPI BOOL WINAPI GetModuleHandleExW (DWORD, LPCWSTR, HMODULE *);

WINBASEAPI VOID WINAPI GetNativeSystemInfo (LPSYSTEM_INFO);
WINBASEAPI BOOL WINAPI GetProcessHandleCount (HANDLE, PDWORD);
WINBASEAPI DWORD WINAPI GetProcessId (HANDLE);
WINBASEAPI BOOL WINAPI GetSystemRegistryQuota (PDWORD, PDWORD);
WINBASEAPI BOOL WINAPI GetSystemTimes (LPFILETIME, LPFILETIME, LPFILETIME);

#define GetSystemWow64Directory __AW_SUFFIXED__(GetSystemWow64Directory)
WINBASEAPI UINT WINAPI GetSystemWow64DirectoryA (LPSTR, UINT);
WINBASEAPI UINT WINAPI GetSystemWow64DirectoryW (LPWSTR, UINT);
WINBASEAPI BOOL WINAPI GetThreadIOPendingFlag (HANDLE, PBOOL);
#define \
GetVolumePathNamesForVolumeName __AW_SUFFIXED__(GetVolumePathNamesForVolumeName)
WINBASEAPI BOOL WINAPI GetVolumePathNamesForVolumeNameA
(LPCSTR, LPSTR, DWORD, PDWORD);
WINBASEAPI BOOL WINAPI GetVolumePathNamesForVolumeNameW
(LPCWSTR, LPWSTR, DWORD, PDWORD);

WINBASEAPI BOOL WINAPI HeapQueryInformation
(HANDLE, HEAP_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);
WINBASEAPI BOOL WINAPI HeapSetInformation
(HANDLE, HEAP_INFORMATION_CLASS, PVOID, SIZE_T);

WINBASEAPI BOOL IsProcessInJob (HANDLE, HANDLE, PBOOL);
WINBASEAPI BOOL WINAPI IsWow64Process (HANDLE, PBOOL);

WINBASEAPI BOOL WINAPI QueryActCtxW
(DWORD, HANDLE, PVOID, ULONG, PVOID, SIZE_T, SIZE_T *);
WINBASEAPI BOOL WINAPI QueryMemoryResourceNotification (HANDLE, PBOOL);

WINBASEAPI void WINAPI ReleaseActCtx (HANDLE);
WINBASEAPI VOID WINAPI RestoreLastError (DWORD);

#define SetFileShortName __AW_SUFFIXED__(SetFileShortName)
WINBASEAPI BOOL WINAPI SetFileShortNameA (HANDLE, LPCSTR);
WINBASEAPI BOOL WINAPI SetFileShortNameW (HANDLE, LPCWSTR);

WINBASEAPI BOOL WINAPI SetFileValidData (HANDLE, LONGLONG);

WINBASEAPI BOOL WINAPI TzSpecificLocalTimeToSystemTime
(LPTIME_ZONE_INFORMATION, LPSYSTEMTIME, LPSYSTEMTIME);

WINBASEAPI BOOL WINAPI ZombifyActCtx (HANDLE);

#if _WIN32_WINNT >= _WIN32_WINNT_WS03
/* Further added features, which became available on the WinNT platform
 * from Windows Server-2003; these were never made available in Win9x.
 */
/* GetFirmwareEnvironmentVariable: previously missing UNICODE vs. ANSI define */
#define \
GetFirmwareEnvironmentVariable __AW_SUFFIXED__(GetFirmwareEnvironmentVariable)
WINBASEAPI DWORD WINAPI GetFirmwareEnvironmentVariableA
(LPCSTR, LPCSTR, PVOID, DWORD);
WINBASEAPI DWORD WINAPI GetFirmwareEnvironmentVariableW
(LPCWSTR, LPCWSTR, PVOID, DWORD);

#define GetDllDirectory __AW_SUFFIXED__(GetDllDirectory)
WINBASEAPI DWORD WINAPI GetDllDirectoryA (DWORD, LPSTR);
WINBASEAPI DWORD WINAPI GetDllDirectoryW (DWORD, LPWSTR);

WINBASEAPI HANDLE WINAPI ReOpenFile (HANDLE, DWORD, DWORD, DWORD);

#define SetDllDirectory __AW_SUFFIXED__(SetDllDirectory)
WINBASEAPI BOOL WINAPI SetDllDirectoryA (LPCSTR);
WINBASEAPI BOOL WINAPI SetDllDirectoryW (LPCWSTR);

#define \
SetFirmwareEnvironmentVariable __AW_SUFFIXED__(SetFirmwareEnvironmentVariable)
WINBASEAPI BOOL WINAPI SetFirmwareEnvironmentVariableA
(LPCSTR, LPCSTR, PVOID, DWORD);
WINBASEAPI BOOL WINAPI SetFirmwareEnvironmentVariableW
(LPCWSTR, LPCWSTR, PVOID, DWORD);

#if _WIN32_WINNT >= _WIN32_WINNT_VISTA
/* Additional features, available only on the WinNT series platforms, from
 * the release of Windows-Vista onwards.
 */
typedef struct _FILE_BASIC_INFO
/* http://msdn.microsoft.com/en-us/library/aa364217%28VS.85%29.aspx */
{ LARGE_INTEGER 		CreationTime;
  LARGE_INTEGER 		LastAccessTime;
  LARGE_INTEGER 		LastWriteTime;
  LARGE_INTEGER 		ChangeTime;
  DWORD 			FileAttributes;
} FILE_BASIC_INFO, *PFILE_BASIC_INFO, *LPFILE_BASIC_INFO;

typedef struct _FILE_STANDARD_INFO
/* http://msdn.microsoft.com/en-us/library/aa364401%28VS.85%29.aspx */
{ LARGE_INTEGER 		AllocationSize;
  LARGE_INTEGER 		EndOfFile;
  DWORD 			NumberOfLinks;
  BOOL				DeletePending;
  BOOL				Directory;
} FILE_STANDARD_INFO, *PFILE_STANDARD_INFO, *LPFILE_STANDARD_INFO;

typedef struct _FILE_NAME_INFO
/* http://msdn.microsoft.com/en-us/library/aa364388%28v=VS.85%29.aspx */
{ DWORD 			FileNameLength;
  WCHAR 			FileName[1];
} FILE_NAME_INFO, *PFILE_NAME_INFO, *LPFILE_NAME_INFO;

typedef struct _FILE_STREAM_INFO
/* http://msdn.microsoft.com/en-us/library/aa364406%28v=VS.85%29.aspx */
{ DWORD 			NextEntryOffset;
  DWORD 			StreamNameLength;
  LARGE_INTEGER 		StreamSize;
  LARGE_INTEGER 		StreamAllocationSize;
  WCHAR 			StreamName[1];
} FILE_STREAM_INFO, *PFILE_STREAM_INFO, *LPFILE_STREAM_INFO;

typedef struct _FILE_COMPRESSION_INFO
/* http://msdn.microsoft.com/en-us/library/aa364220%28v=VS.85%29.aspx */
{ LARGE_INTEGER 		CompressedFileSize;
  WORD				CompressionFormat;
  UCHAR 			CompressionUnitShift;
  UCHAR 			ChunkShift;
  UCHAR 			ClusterShift;
  UCHAR 			Reserved[3];
} FILE_COMPRESSION_INFO, *PFILE_COMPRESSION_INFO, *LPFILE_COMPRESSION_INFO;

typedef struct _FILE_ATTRIBUTE_TAG_INFO
/* http://msdn.microsoft.com/en-us/library/aa364216%28v=VS.85%29.aspx */
{ DWORD 			FileAttributes;
  DWORD 			ReparseTag;
} FILE_ATTRIBUTE_TAG_INFO, *PFILE_ATTRIBUTE_TAG_INFO, *LPFILE_ATTRIBUTE_TAG_INFO;

typedef struct _FILE_ID_BOTH_DIR_INFO
/* http://msdn.microsoft.com/en-us/library/aa364226%28v=VS.85%29.aspx */
{ DWORD 			NextEntryOffset;
  DWORD 			FileIndex;
  LARGE_INTEGER 		CreationTime;
  LARGE_INTEGER 		LastAccessTime;
  LARGE_INTEGER 		LastWriteTime;
  LARGE_INTEGER 		ChangeTime;
  LARGE_INTEGER 		EndOfFile;
  LARGE_INTEGER 		AllocationSize;
  DWORD 			FileAttributes;
  DWORD 			FileNameLength;
  DWORD 			EaSize;
  CCHAR 			ShortNameLength;
  WCHAR 			ShortName[12];
  LARGE_INTEGER 		FileId;
  WCHAR 			FileName[1];
} FILE_ID_BOTH_DIR_INFO, *PFILE_ID_BOTH_DIR_INFO, *LPFILE_ID_BOTH_DIR_INFO;

typedef struct _FILE_REMOTE_PROTOCOL_INFO
/* http://msdn.microsoft.com/en-us/library/dd979524%28v=VS.85%29.aspx */
{ USHORT			StructureVersion;
  USHORT			StructureSize;
  ULONG  			Protocol;
  USHORT			ProtocolMajorVersion;
  USHORT			ProtocolMinorVersion;
  USHORT			ProtocolRevision;
  USHORT			Reserved;
  ULONG  			Flags;
  struct
  { ULONG			  Reserved[8];
  }				GenericReserved;
  struct
  { ULONG			  Reserved[16];
  }				ProtocolSpecificReserved;
} FILE_REMOTE_PROTOCOL_INFO, *PFILE_REMOTE_PROTOCOL_INFO, *LPFILE_REMOTE_PROTOCOL_INFO;

typedef enum _DEP_SYSTEM_POLICY_TYPE
{ AlwaysOn,
  AlwaysOff,
  OptIn,
  OptOut
} DEP_SYSTEM_POLICY_TYPE;

typedef enum _FILE_INFO_BY_HANDLE_CLASS
/* http://msdn.microsoft.com/en-us/library/aa364228%28v=VS.85%29.aspx */
{ FileBasicInfo,
  FileStandardInfo,
  FileNameInfo,
  FileRenameInfo,
  FileDispositionInfo,
  FileAllocationInfo,
  FileEndOfFileInfo,
  FileStreamInfo,
  FileCompressionInfo,
  FileAttributeTagInfo,
  FileIdBothDirectoryInfo,
  FileIdBothDirectoryRestartInfo,
  FileIoPriorityHintInfo,
  FileRemoteProtocolInfo,
  MaximumFileInfoByHandlesClass
} FILE_INFO_BY_HANDLE_CLASS, *PFILE_INFO_BY_HANDLE_CLASS;

#define CreateSymbolicLink __AW_SUFFIXED__(CreateSymbolicLink)
WINBASEAPI BOOL WINAPI CreateSymbolicLinkA (LPCSTR, LPCSTR, DWORD);
WINBASEAPI BOOL WINAPI CreateSymbolicLinkW (LPCWSTR, LPCWSTR, DWORD);

/* http://msdn.microsoft.com/en-us/library/aa364953%28VS.85%29.aspx */
WINBASEAPI BOOL WINAPI GetFileInformationByHandleEx
(HANDLE, FILE_INFO_BY_HANDLE_CLASS, LPVOID, DWORD);

/* http://msdn.microsoft.com/en-us/library/aa364962%28VS.85%29.aspx */
#define GetFinalPathNameByHandle __AW_SUFFIXED__(GetFinalPathNameByHandle)
WINBASEAPI DWORD WINAPI GetFinalPathNameByHandleA (HANDLE, LPSTR, DWORD, DWORD);
WINBASEAPI DWORD WINAPI GetFinalPathNameByHandleW
(HANDLE, LPWSTR, DWORD, DWORD);

/* https://msdn.microsoft.com/en-us/library/aa904937%28v=vs.85%29.aspx */
/* Note: MSDN does not offer any detail of how SRWLOCK should be defined,
 * (other than stating that it is a structure with the size of a pointer);
 * an opaque generic pointer type appears to be sufficient.
 */
typedef PVOID SRWLOCK, *PSRWLOCK;

void WINAPI InitializeSRWLock (PSRWLOCK);
void WINAPI AcquireSRWLockExclusive (PSRWLOCK);
void WINAPI AcquireSRWLockShared (PSRWLOCK);
void WINAPI ReleaseSRWLockExclusive (PSRWLOCK);
void WINAPI ReleaseSRWLockShared (PSRWLOCK);

/* https://msdn.microsoft.com/en-us/library/ms682052%28v=vs.85%29.aspx */
/* Note: once again, MSDN fails to document this, but an opaque generic
 * pointer type appears to suffice.
 */
typedef PVOID CONDITION_VARIABLE, *PCONDITION_VARIABLE;

void WINAPI InitializeConditionVariable (PCONDITION_VARIABLE);
BOOL WINAPI SleepConditionVariableCS (PCONDITION_VARIABLE, PCRITICAL_SECTION, DWORD);
BOOL WINAPI SleepConditionVariableSRW (PCONDITION_VARIABLE, PSRWLOCK, DWORD, ULONG);
void WINAPI WakeAllConditionVariable (PCONDITION_VARIABLE);
void WINAPI WakeConditionVariable (PCONDITION_VARIABLE);

#if _WIN32_WINNT >= _WIN32_WINNT_WIN7
/* Additional features, available only on the WinNT series platforms, from
 * the release of Windows-7 onwards.
 */
WINBASEAPI BOOL WINAPI GetProcessDEPPolicy (HANDLE, LPDWORD, PBOOL);
WINBASEAPI DEP_SYSTEM_POLICY_TYPE WINAPI GetSystemDEPPolicy (void);

WINBASEAPI BOOL WINAPI SetProcessDEPPolicy (DWORD);

/* https://msdn.microsoft.com/en-us/library/aa904937%28v=vs.85%29.aspx */
BOOLEAN WINAPI TryAcquireSRWLockExclusive (PSRWLOCK);
BOOLEAN WINAPI TryAcquireSRWLockShared (PSRWLOCK);

#endif	/* Win7 and later */
#endif	/* Windows Vista and later */
#endif	/* Windows Server-2003 and later */
#endif	/* WinXP and later; not Win9x */
#endif	/* Win2K and later, but not Win9x */
#endif	/* Win98, Win2K, and later */

#endif	/* ! RC_INVOKED */

_END_C_DECLS

#endif	/* !_WINBASE_H: $RCSfile: winbase.h,v $: end of file */
