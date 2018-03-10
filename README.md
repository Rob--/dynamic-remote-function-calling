# dynamic-remote-function-calling

The purpose of this repo is to house two projects that work together to demonstrate dynamically calling a function in a target process given only it's address.

---

#### Target Process
This project contains the function that will be called remotely from the "External Caller" project. When run, this program will output the relative address of the function that will be called from the base of the process. This offset is then defined inside of "External Caller" and is used to calculate the absolute address of the function to call.

#### External Caller
This project is the application that will actually generate the shellcode, write it to the target application and execute it.

Given the function to be called inside of "Target Process":
```cpp
void functionToRemotelyCall(int a, bool b, std::string c);
```

Arguments can be dynamically generated and used to execute the function:
```cpp
std::vector<Arg> args = {
  { T_INT, &a },
  { T_BOOL, &b },
  { T_STRING, &c },
};

call(pHandle, args, T_VOID, functionAddress);
```

The application will calculate the absolute address of the function given it's relative address from the base of the target process.

---

#### Notes
This demonstration was made to help [this issue](https://github.com/Rob--/memoryjs/issues/6) from [memoryjs](https://github.com/Rob--/memoryjs).

Currently strings can be written to the target process but we cannot define the size/length of the string.

Credits to [xetrics](https://github.com/xetrics).