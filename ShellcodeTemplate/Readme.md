# Shellcode Template

An easily modifiable shellcode template for Windows x64/x86

### How does it work? 
This template is heavily based on [Austin Hudson's (aka SecIdiot)](https://twitter.com/ilove2pwn_) [TitanLdr](https://github.com/SecIdiot/TitanLdr)
It compiles the project into a PE Executable and extracts the .text section

### Example
The entrypoint of the shellcode looks like this. Of course, this can be changed for your need. 
First we need to initialize needed libraries and functions by using our custom written GetModuleHandle and GetProcAddress.
```c
SEC( text, B ) VOID Entry( VOID ) 
{
    INSTANCE Instance = { };

    Instance.Modules.Kernel32   = LdrModulePeb( HASH_KERNEL32 ); 
    Instance.Modules.Ntdll      = LdrModulePeb( HASH_NTDLL ); 

    if ( Instance.Modules.Kernel32 != NULL )
    {
        // Load needed functions
        Instance.Win32.LoadLibraryA = LdrFunction( Instance.Modules.Kernel32, 0xb7072fdb );

        // Load needed Libraries
        Instance.Modules.User32     = Instance.Win32.LoadLibraryA( GET_SYMBOL( "User32" ) );

        if ( Instance.Modules.User32 != NULL ) 
        {
            Instance.Win32.MessageBoxA = LdrFunction( Instance.Modules.User32, 0xb303ebb4 );
        } 
    }
    
    // ------ Code ------
    Instance.Win32.MessageBoxA( NULL, GET_SYMBOL( "Hello World" ), GET_SYMBOL( "MessageBox Title" ), MB_OK );
}
```
Btw as you can see we can use normal strings in our shellcode. This is because we include the .rdata section into our shellcode at linking time.
And GET_SYMBOL gets the pointer to the function or string via its relative offset to GetRIP()

![Preview](https://github.com/Cracked5pider/ShellcodeTemplate/blob/main/Img/debugger.png)

### Get Started
Clone this project and you are ready to start
```
git clone https://www.github.com/Cracked5pider/ShellcodeTemplate
```
Next you would need to change the project name in the makefile from `ShellcodeTemplate` to whatever you want
Then you can compile the project by using make
```
make        // to compile x64 and x86
make x64    // to compile only x64
make x86    // to compile only x86
```

### Credit 
Huge credit goes to [Austin Hudson (aka SecIdiot)](https://twitter.com/ilove2pwn_)!!!
