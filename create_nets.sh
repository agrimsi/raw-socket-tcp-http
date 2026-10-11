for net in lan_a lan_b lan_c link_d; do
  cat <<EOF > $net.xml
  <network>
    <name>$net</name>
    <bridge name='virbr-$net' stp='on' delay='0'/>
  </network>
EOF
  virsh net-define $net.xml
  virsh net-start $net
  virsh net-autostart $net
done
