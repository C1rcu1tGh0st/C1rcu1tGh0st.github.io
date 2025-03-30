---
title: Unpacking DarkWatchman A JavaScript RAT in the Wild
date: 2025-03-29 
categories: [malware analysis, ]
tags: [darkwatchman, malware, javascript, rat]     # TAG names should always be lowercase
---

DarkWatchman is a stealthy JavaScript-based RAT that first appeared in 2021. It operates filelessly, using the Windows Registry to store payloads, keylogger data, and configuration, making detection difficult. With features like keylogging, system reconnaissance, and remote command execution, it provides attackers persistent access to infected machines. This analysis breaks down its execution, stealth tactics, and C2 communication. The sample under analysis can be found here: [efde274a71cb59f75ece16678bf10427a79e7a39ad244f244041a6038be0c2e9](https://bazaar.abuse.ch/sample/efde274a71cb59f75ece16678bf10427a79e7a39ad244f244041a6038be0c2e9/)

# Technical Analysis

## Initial Stage

The initial stage of this sample is an obfuscated .NET binary. Running the de4dot tool against it reveals that it is packed with the DeepSea .NET packer, which can be de-obfuscated using the same tool. The sample decrypts data from its resources and dynamically loads a DLL named `TL`, then calls a method from this newly loaded DLL.

This DLL is also obfuscated with DeepSea, making de4dot useful again for analysis. The method `NAJqp8Xm9` is responsible for decrypting and loading another DLL named `Montero`, which is packed with ConfuserEx. It then invokes the method `qj0jaev55p`, which handles decrypting the second-stage payload.

![](assets/ss/darkwatchman/1.png) 
*Fig 1: View from DIE tool* 

![](assets/ss/darkwatchman/2.png) 
*Fig 2: deepsea packer detected by de4dot* 

![](assets/ss/darkwatchman/3.png) 
*Fig 3: dynamically loaded TL module* 

![](assets/ss/darkwatchman/4.png) 
*Fig 4: the obfuscated method `NAJqp8Xm9` that is called* 

![](assets/ss/darkwatchman/5.png) 
*Fig 5: the method `NAJqp8Xm9` after de-obfuscation* 

![](assets/ss/darkwatchman/6.png) 
*Fig 6: new dll named `Montero` loaded* 

![](assets/ss/darkwatchman/7.png) 
*Fig 7: `Montero` packed with ConfuserEx* 

![](assets/ss/darkwatchman/8.png) 
*Fig 8: `Montero` dll invokes `qj0jaev55p`* 

![](assets/ss/darkwatchman/9.png) 
*Fig 9: obfuscated `qj0jaev55p` method* 

![](assets/ss/darkwatchman/10.png) 
*Fig 10: xor decryption method and decrypted binary* 

## Second Stage

The second-stage binary is also a .NET executable. Upon execution, it generates a random integer between 3 and 10 and creates that many files, each filled with random bytes ranging from 5,000 to 25,599 bytes. These files are stored in the C:\Users\Username\AppData\Local\Temp directory.

Next, the sample decodes a Base64-encoded string and writes the output to C:\Users\Username\AppData\Local\dynwrapx.dll. Additionally, it creates two more files in C:\Users\Username\AppData\Local\Data, which are decoded from Base64 and decrypted using AES in CBC mode:

* 127195602(this file has encrypted keylogger code)

* 3610022385 (contains obfuscated Jscript)

The file 3610022385 is an obfuscated JavaScript file responsible for decrypting the final-stage payload. It is executed using cmd.exe with the following command: `/C wscript.exe /E:jscript C:\Users\Username\AppData\Local\Data\3610022385 188` Here, 188 is the argument passed to the script, likely influencing the decryption or execution logic of the final stage.

![](assets/ss/darkwatchman/11.png) 
*Fig 11: writing bytes to `dynwrapx.dll`* 

![](assets/ss/darkwatchman/12.png) 
*Fig 12: writing bytes to `127195602`* 

![](assets/ss/darkwatchman/13.png) 
*Fig 13: writing bytes to `3610022385` and runs the obfuscated Javascript using cmd* 

Upon analyzing the JavaScript file, it is clearly obfuscated. However, after de-obfuscation, it reveals its main function: decrypting the final-stage payload.

The decryption key is stored in the Windows Registry under:

`HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM\fjhsfgds`

The specific key used for decryption is 207_11_90_55, as shown in Figure 15. Once decrypted, the script executes the final-stage JavaScript payload, which is responsible for deploying the DarkWatchman RAT.

Key Takeaways:
* Registry-based Key Storage: Hiding the decryption key in the registry makes detection and forensic analysis more difficult.

* Final Execution: The decrypted payload is executed dynamically, leading to the full deployment of DarkWatchman.

* Multi-Stage Approach: This attack chain involves multiple layers of obfuscation and encryption to evade security mechanisms.

![](assets/ss/darkwatchman/14.png) 
*Fig 14: `3610022385` obfuscated* 

![](assets/ss/darkwatchman/15.png) 
*Fig 15: `3610022385` de-obfuscated* 

## DarkWatchman RAT

Examining the code reveals that it initializes several global variables using the init_globals() function. Shortly after, the sample begins its installation process.

Registry-Based Configuration & Keylogger Storage:
The malware stores its configuration data and Base64-obfuscated keylogger code in:
`HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM`

The registry keys are named dynamically based on the system’s MachineGuid. Specifically, the first 8 characters of the MachineGuid are extracted and appended with a character from the following set:

`('0', '1', 'a', 's', 'z', 'p', 'h', 'c', 'b', 'r', 't', 'j', 'v', 'd', '00')`

Purpose of few Registry Keys:

`uid + 0` → Used for installation

`uid + 1` → Stores the compiled keylogger code

`uid + h` → Clears browser history

`uid + c` → Stores C2 (Command & Control) configuration 


![](assets/ss/darkwatchman/16.png) 
*Fig 16: `init_globals()` function* 

![](assets/ss/darkwatchman/17.png) 
*Fig 17: `get_uid()` method that gets first 8 character of machineGuid* 


![](assets/ss/darkwatchman/18.png) 
*Fig 18: view of the registry DWM with the configs for base64 encoded keylogger code and captured data* 

The install function in DarkWatchman ensures persistence and evasion by modifying system settings. It first creates a Windows Defender exclusion path, preventing detection and allowing the malware to operate undisturbed. Next, it copies itself to the Temp folder, naming the file uid + 0.js, where uid is derived from the MachineGuid. This copied script serves as the main execution point for persistence. To maintain long-term access, the malware sets up a Task Scheduler entry, ensuring that the JScript file (uid + 0.js) runs automatically at scheduled intervals, even after system reboots, then it calls `keylogger_to_registry()` function 


![](assets/ss/darkwatchman/19.png) 
*Fig 19: `install()` function* 

![](assets/ss/darkwatchman/20.png) 
*Fig 20: `create_autostart_task()` function* 


## Keylogger

The keylogger in DarkWatchman remains encrypted until execution. The file 127195602, written to disk during Stage 2, contains the encrypted keylogger code. This file is decrypted, and the resulting payload is stored in the Windows Registry under `uid + 1`. Once decrypted, the malware deletes `127195602` to remove traces of its presence.

Decoding the Base64 string reveals that the keylogger is written in C# and is capable of capturing both keystrokes and clipboard data. The collected clipboard and keystroke data are then stored in the registry key `uid + a`, further reinforcing DarkWatchman’s stealthy, fileless approach to data exfiltration.

![](assets/ss/darkwatchman/21.png) 
*Fig 21: gets the data from the decrypts it and writes the base64 data to registry* 

![](assets/ss/darkwatchman/22.png) 
*Fig 22: run() method of the decrypted keylogger* 

![](assets/ss/darkwatchman/23.png) 
*Fig 23: capture clipboard function* 

![](assets/ss/darkwatchman/24.png) 
*Fig 24: keyboard hook procedure* 

## C2 Setup 

DarkWatchman dynamically constructs its Command and Control (C2) server URL and sets up a connection to it. Before establishing communication, the malware validates the C2 server’s availability by pinging the generated links. If a C2 server is reachable, the malware stores its details in the Windows Registry under the key `uid + c`. 

 ![](assets/ss/darkwatchman/25.png) 
*Fig 25: gets c2 link and save it to registry key `uid +c`* 

 ![](assets/ss/darkwatchman/26.png) 
*Fig 26: initialized data to constrict c2* 

 ![](assets/ss/darkwatchman/29.png) 
*Fig 27: functions that handles c2 communication and sends data* 


## Other Features 

DarkWatchman offers several remote administration commands, allowing attackers to control the infected system. Some of the key commands include:

* execute_exe – Runs an executable file on the compromised machine.

* set_cc_url – Updates the Command and Control (C2) server URL dynamically.

* eval_js – Executes JavaScript code remotely.

* execute_ps – Runs PowerShell commands, enabling deeper system control.

* stop_self – Terminates the malware’s execution and removes persistence.

As seen in Figure 28, these commands provide remote access, execution capabilities, and self-termination features, making DarkWatchman a highly flexible and stealthy Remote Access Trojan (RAT).

 ![](assets/ss/darkwatchman/27.png) 
*Fig 28: other functions* 

 ![](assets/ss/darkwatchman/28.png) 
*Fig 29: send info functions* 

## Conclusion

DarkWatchman is a highly evasive fileless malware, and while this blog does not cover all of its features, it showcases its use of registry-based storage, scheduled tasks, and Windows Defender exclusions for persistence. Its keylogger, remote commands, and dynamic C2 setup make it a significant threat. Detecting such malware requires close monitoring of registry modifications, PowerShell activity, and unusual network behavior to prevent infections.