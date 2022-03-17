cd ../../../
if [ ! -d "tutorials" ]; then
  git clone https://github.com/p4lang/tutorials
fi
ln -s $PWD/tutorials/utils $PWD/NetHCF/utils
cd ./NetHCF/bmv2/switch_16
