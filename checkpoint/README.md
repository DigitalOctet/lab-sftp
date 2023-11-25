# Mini SFTP Client

### CP1
![CP1](./ckpt_1.jpg)

The server identification string is `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4`.

### CP2
![CP2](./ckpt_2.jpg)

We can see the negotiate cipher suite in above figure.

### CP3
![CP3](./ckpt_3.jpg)

The above figure is the screenshot from wireshark. We can see that after the New Keys message, all messages are encrypted.

### CP4
![CP4](./ckpt_4.jpg)

When we input wrong password, the terminal will show `Permission denied, please try again.`. When we input correct password, the server grants access to the client.

### CP5

![CP5](./ckpt_5.png)

Local channel number was 1, and remote channel number was 0.

Local window size was 64000, and remote window size was 0 when the channel was firstly established. After the client requested an SFTP subsystem, the remote window was adjusted to 2097152.

### CP6

![CP6](./ckpt_6.png)

The client connected to the localhost and successfully uploaded and downloaded `client.c`. We compared the downloaded and uploaded files with the original file using command `diff`. Empty outputs mean that these three files are exactly the same.
