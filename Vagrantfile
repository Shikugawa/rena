Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/impish64"
  config.vm.define :impish64
  config.vm.hostname = "impish64"
  config.vm.synced_folder ".", "/rena"
  config.vm.provision "shell", inline: <<-SHELL
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    apt-get install -y cargo bridge-utils
    for f in bridge-nf-*; do echo 0 > $f; done
    sudo ebtables -A INPUT --log-level debug --log-arp --log-prefix IN -j ACCEPT
    sudo ebtables -A FORWARD --log-level debug --log-arp --log-prefix FW -j ACCEPT
  SHELL
end
