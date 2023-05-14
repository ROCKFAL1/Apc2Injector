# Apc2Injector
Example of injection with [QueueUserAPC2](https://learn.microsoft.com/ru-ru/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc2) (Works only starting from Windows 11)

# Dependencies
- [wil](https://github.com/microsoft/wil) (RAII handles is very convenient)
- [xbyak](https://github.com/herumi/xbyak) (To generate a shellcode for APC)

# Usage 
```console
Apc2Injector {dll_path} {exe_name}  
```
`dll_path` - Path to dll payload. Can be a relative path  
`exe_name` - Name of target process.  
  
For example: 
```console
 Apc2Injector Apc2Dll.dll explorer.exe
```

# How does it work?
### Main stages
1. Defining target process and getting handle
2. Loading path to dll into target process
3. Loading shell code of APC function to target process
4. Take handle on target process thread (I prefer to take main thread)
5. Call `QueueUserAPC2`

# TODO
- [ ] Support of Wow64 targets
- [ ] Detailed description of injection method
- [ ] Add more comments (?)

