$Section.Add(1,[PSCustomObject]@{
    PSTypeName = 'CISBenchmark.Section'
    Name = 'Install'
    Description = 'This section contains recommendations for base ESXi install.'
    Content = @{}
})

#region (L1) Ensure ESXi is properly patched (Manual)
$Section[1].Content.Add(1,[PSCustomObject]@{
    PSTypeName = 'CISBenchmark.Test'
    Name = 'Ensure ESXi is properly patched (Manual)'
    AppliesTo = 'L1'
    Description = 'VMware Lifecycle Manager is a tool which may be utilized to automate patch management for vSphere hosts and virtual machines. Creating a baseline for patches is a good way to ensure all hosts are at the same patch level. VMware also publishes advisories on security patches and offers a way to subscribe to email alerts for them.'
    Rationale = 'By staying up to date on ESXi patches, vulnerabilities in the hypervisor can be mitigated. An educated attacker can exploit known vulnerabilities when attempting to attain access or elevate privileges on an ESXi host.'
    Impact = 'ESXi servers must be in Maintenance Mode to apply patches. This implies all VMs must be moved or powered off on the ESXi server, so the patching process may necessitate having brief outages.'
})
#endregion

#region (L1) Ensure ESXi is properly patched (Manual)
$Section[1].Content.Add(2,[PSCustomObject]@{
    PSTypeName = 'CISBenchmark.Test'
    Name = 'Ensure the Image Profile VIB acceptance level is configured 
    properly (Automated)'
    AppliesTo = 'L1'
    Description = 'A VIB (vSphere Installation Bundle) is a collection of files that are packaged into an archive. The VIB contains a signature file that is used to verify the level of trust. The ESXi Image Profile supports four VIB acceptance levels:

1. VMware Certified - VIBs created, tested, and signed by VMware
2. VMware Accepted - VIBs created by a VMware partner but tested and signed by VMware
3. Partner Supported - VIBs created, tested, and signed by a certified VMware partner
4. Community'
    Rationale = 'The ESXi Image Profile should only allow signed VIBs because an unsigned VIB represents untested code installed on an ESXi host. Also, use of unsigned VIBs will cause hypervisor Secure Boot to fail to configure. Community Supported VIBs do not have digital signatures. To protect the security and integrity of your ESXi hosts, do not allow unsigned (CommunitySupported) VIBs to be installed on your hosts.'
    Impact = 'Unsigned (Community Supported) VIBs will not be able to be utilized on a host.'
})
#endregion