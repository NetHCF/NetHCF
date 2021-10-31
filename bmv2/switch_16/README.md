# NetHCF implementation with P4_16

## 

Run with [P4-Tutorial](https://github.com/p4lang/tutorials) framework, please make sure that you have installed all the requirements for P4 tutorial.

#### Prepare

```shell
git clone https://github.com/NetHCF/NetHCF
git clone https://github.com/p4lang/tutorials
ln -s $PWD/tutorials/utils $PWD/NetHCF/utils
cd ./NetHCF/bmv2/switch_16
```

or 

```shell
git clone https://github.com/NetHCF/NetHCF
cd NetHCF/switch_16
sh init.sh
```

#### Run

In one terminal:

```shell
make
```

In another terminal:

```shell
cd NetHCF/bmv2/controller
sudo python controller.py
```

## Automatical Conversion from P4_14 to P4_16

This P4_16 code refers to the automatically generated code by p4c, which is

```shell
cd NetHCF/bmv2/switch/p4src
p4test --p4v 14 --pp nethcf16.p4 nethcf.p4
```
