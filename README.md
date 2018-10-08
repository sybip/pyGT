# pyGT
An unofficial open source Python library for operating goTenna Mesh devices over Bluetooth LE

Requires:
  bluepy (pip install bluepy)

```
import gtdevice

gotenna = gtdevice.goTennaDev(MAC)
gotenna.initialize()
(resCode, resData) = gotenna.execute(opCode, opData)
# ...
gotenna.disconnect()
```

Not affiliated with goTenna inc. This software may brick your device and void your warranty. 
