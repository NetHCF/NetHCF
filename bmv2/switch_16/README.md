# NetHCF implementation with P4_16

Run with [P4-Tutorial](https://github.com/p4lang/tutorials) framework

```shell
git clone https://github.com/NetHCF/NetHCF
git clone https://github.com/p4lang/tutorials
ln -s NetHCF/bmv2/switch_16 tutorials/exercises/NetHCF
cd tutorials/exercises/NetHCF
make
```

In another terminal:
```shell
cd NetHCF/bmv2/controller
sudo python controller.py
```
