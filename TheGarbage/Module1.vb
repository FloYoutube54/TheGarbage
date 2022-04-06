Imports System.Net
Imports System.Net.NetworkInformation
Imports System.Net.Sockets
Imports NicolasDorier
Imports TheGarbage.TheGarbage.Network.Packet
Imports Microsoft.WindowsAPICodePack.Taskbar
Imports Monitor = TheGarbage.TheGarbage.Network.PacketMon.Monitor


Module Module1

    Private WithEvents packetmon As Monitor

    Sub Main()
        AddHandler Console.CancelKeyPress, AddressOf ReturnToMenu
        Console.Clear()
        WriteHeader()
        Console.WriteLine("Welcome to The Garbage! Type the number of the choosen function and press enter:")
        Console.WriteLine(" > 1 ip scanner")
        Console.WriteLine(" > 2 port scanner")
        Console.WriteLine(" > 3 hostname lookup")
        Console.WriteLine(" > 4 device scanner")
        Console.WriteLine(" X 5 packet sniffer")
        Console.WriteLine(" > 0 exit")
        Console.WriteLine("")
        Console.Write("> ")
        Dim choosen = Console.ReadLine()
        If choosen = "1" Then
            Scanner()
        ElseIf choosen = "2" Then
            PortScanner()
        ElseIf choosen = "3" Then
            hostnameLookup()
        ElseIf choosen = "4" Then
            deviceScanner()
        ElseIf choosen = "5" Then
            packetSniffer()
        ElseIf choosen = "0" Then
            End
        Else
            Console.WriteLine("Invalid input")
            Main()
        End If
    End Sub

    Function ReturnToMenu(ByVal sender As Object, ByVal args As ConsoleCancelEventArgs)
        args.Cancel = False
        Console.Clear()
        Main()
    End Function

    Public Function Scanner()
        Console.Clear()
        WriteHeader()
        Console.WriteLine("IP Scanner")
        Console.WriteLine("")
        Console.WriteLine("Enter the ip range you want to scan:")
        Console.Write("> ")
        Dim ipRange = Console.ReadLine()
        Console.WriteLine("")
        Console.WriteLine("Enter the timeout in milliseconds:")
        Console.Write("> ")
        Dim timeout = Console.ReadLine()
        Dim ipRangeSplit = ipRange.Split("-")
        Dim ipStart = ipRangeSplit(0)
        Dim ipEnd = ipRangeSplit(1)
        Dim ipStartSplit = ipStart.Split(".")
        Dim ipEndSplit = ipEnd.Split(".")
        Dim ipStart1 = ipStartSplit(0)
        Dim ipStart2 = ipStartSplit(1)
        Dim ipStart3 = ipStartSplit(2)
        Dim ipStart4 = ipStartSplit(3)
        Dim ipEnd1 = ipEndSplit(0)
        Dim ipEnd2 = ipEndSplit(1)
        Dim ipEnd3 = ipEndSplit(2)
        Dim ipEnd4 = ipEndSplit(3)
        Dim ipStartInt = Convert.ToInt32(ipStart1)
        Dim ipEndInt = Convert.ToInt32(ipEnd1)
        Dim ipStart2Int = Convert.ToInt32(ipStart2)
        Dim ipEnd2Int = Convert.ToInt32(ipEnd2)
        Dim ipStart3Int = Convert.ToInt32(ipStart3)
        Dim ipEnd3Int = Convert.ToInt32(ipEnd3)
        Dim ipStart4Int = Convert.ToInt32(ipStart4)
        Dim ipEnd4Int = Convert.ToInt32(ipEnd4)
        Dim ipList As New List(Of String)
        For i = ipStartInt To ipEndInt
            For j = ipStart2Int To ipEnd2Int
                For k = ipStart3Int To ipEnd3Int
                    For l = ipStart4Int To ipEnd4Int
                        Dim ip = i & "." & j & "." & k & "." & l
                        ipList.Add(ip)
                    Next
                Next
            Next
        Next
        Console.WriteLine("")
        Console.WriteLine("Scanning...")
        Console.WriteLine("")
        Dim upIps As New List(Of IPEntry)
        Dim m As Integer = 0
        Dim totalTime As Integer = 0
        Dim tb As TaskbarManager = TaskbarManager.Instance
        tb.SetProgressState(TaskbarProgressBarState.Normal)
        Dim ipsDiscoveredSinceLastUpdate As Integer = 0
        For Each ip In ipList
            tb.SetProgressValue(m, ipList.Count)
            'calculate remaining time
            Dim remainingTime = (ipList.Count - m) * (Convert.ToInt32(timeout) / 1000)
            Dim remainingTimeHours = TimeSpan.FromSeconds(remainingTime).Hours
            Dim remainingTimeMin = TimeSpan.FromSeconds(remainingTime).Minutes
            Dim remainingTimeSec = TimeSpan.FromSeconds(remainingTime).Seconds
            Dim ping = New Ping()
            Dim reply = ping.Send(ip, timeout)
            If reply.Status = IPStatus.Success Then
                ipsDiscoveredSinceLastUpdate += 1
                Dim ipEntry = New IPEntry
                ipEntry.IP = ip
                Try
                    ipEntry.Hostname = Dns.GetHostEntry(ip).HostName
                Catch ex As Exception
                    ipEntry.Hostname = "Unknown"
                End Try
                upIps.Add(ipEntry)
                totalTime += reply.RoundtripTime
            End If
            m += 1
            Console.SetCursorPosition(0, Console.CursorTop - 1) 'move cursor to the beginning of the line
            Console.Write(New String(" "c, Console.WindowWidth)) 'clear line
            Console.SetCursorPosition(0, Console.CursorTop - 1) 'move cursor to the beginning of the line
            Console.SetCursorPosition(0, Console.CursorTop - 1) 'move cursor to the beginning of the line
            Console.Write(New String(" "c, Console.WindowWidth)) 'clear line
            Console.SetCursorPosition(0, Console.CursorTop - 1) 'move cursor to the beginning of the line
            'print progress bar
            Console.WriteLine("[" & New String("="c, (m / ipList.Count * 100)) & New String(" "c, (100 - (m / ipList.Count * 100))) & "] " & Decimal.Round(m / ipList.Count * 100, 2, MidpointRounding.AwayFromZero) & "% (" & upIps.Count & " up)")
            Console.WriteLine("remaining time: " & Decimal.Round(remainingTimeHours) & " h " & Decimal.Round(remainingTimeMin) & " m " & Decimal.Round(remainingTimeSec) & " s ")
        Next
        Dim averageTime = totalTime / upIps.Count
        'print statistics
        Console.WriteLine("")
        Console.WriteLine("Statistics:")
        Console.WriteLine(" > " & upIps.Count & " up")
        Console.WriteLine(" > " & ipList.Count - upIps.Count & " down")
        Console.WriteLine(" > " & averageTime & "ms average response time")
        'write results to file
        Dim fileName = "ipScanner_" & DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss") & ".txt"
        Dim file = My.Computer.FileSystem.OpenTextFileWriter(fileName, True)
        For Each ip In upIps
            file.WriteLine("IP: " & ip.IP & " Hostname: " & ip.Hostname)
        Next
        file.Flush()
        file.Close()
        tb.SetProgressState(TaskbarProgressBarState.NoProgress)
        Console.WriteLine("")
        Console.WriteLine("Press enter to return to the main menu")
        Console.ReadKey()
        Main()
    End Function

    Private Function GetMacAddress(ip As String) As String
        Dim macAddress As String = ""
        Dim macAddressList As New List(Of String)
        Dim ipAddress As IPAddress = IPAddress.Parse(ip)
        Dim arp = New ARPHelper()
        Dim macAddressBytes = arp.GetMacAddress(ipAddress)
        For Each macAddressByte In macAddressBytes
            macAddress += macAddressByte.ToString("X2")
            macAddress += "-"
        Next
        macAddress = macAddress.Remove(macAddress.Length - 1)
        Return macAddress
    End Function

    Public Function PortScanner()
        'clear console and print header
        Console.Clear()
        WriteHeader()
        Console.WriteLine("Port Scanner")
        Console.Write("Enter the ip you want to scan: ")
        Dim ipToScan = Console.ReadLine()
        Console.WriteLine("Choose the method you want to use:")
        Console.WriteLine(" > 1 All ports")
        Console.WriteLine(" > 2 Specific ports")
        Console.Write("> ")
        Dim method = Console.ReadLine()
        Console.WriteLine("")
        Console.WriteLine("")
        If method = "1" Then
            'propose a menu that allow user to choose fat or slow scan
            Console.WriteLine("Choose the scan method:")
            Console.WriteLine(" > 1 Fast scan")
            Console.WriteLine(" > 2 Slow scan")
            Console.Write("> ")
            Dim scanMethod = Console.ReadLine()
            'propose a menu that allow user to save results in a file or display them on the console
            Console.WriteLine("Choose the output method:")
            Console.WriteLine(" > 1 Save to file")
            Console.WriteLine(" > 2 Display on console")
            Console.Write("> ")
            Dim outputMethod = Console.ReadLine()
            Dim filename As String
            If outputMethod = "1" Then
                Console.WriteLine("")
                Console.Write("Enter the name of the file: ")
                filename = Console.ReadLine()
            End If
            If scanMethod = "1" Then
                'scan all ports on the network
                Dim thisIp As IPAddress = Net.IPAddress.Parse(ipToScan)
                Dim clients As New List(Of TcpClient)
                For i As Integer = 1 To 65535
                    Dim client As New TcpClient()
                    Try
                        Dim result As IAsyncResult = client.BeginConnect(thisIp.ToString(), i, Nothing, Nothing) 'try to connect to the port
                        Dim th As Threading.WaitHandle = result.AsyncWaitHandle
                        Try
                            If result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(1), False) Then
                                If client.Connected Then
                                    clients.Add(client)
                                End If
                            End If
                        Catch ex As Exception
                            th.Close()
                        End Try
                        'add client to list
                    Catch ex As Exception
                        Debug.WriteLine(ex.Message)
                    End Try
                    'clear last line and print progress bar
                    Console.SetCursorPosition(0, Console.CursorTop - 1) 'move cursor to the beginning of the line
                    Console.Write(New String(" "c, Console.WindowWidth)) 'clear line
                    Console.SetCursorPosition(0, Console.CursorTop - 1) 'move cursor to the beginning of the line
                    'print progress bar
                    Console.WriteLine("[" & New String("="c, (i / 65535 * 100)) & New String(" "c, (100 - (i / 65535 * 100))) & "] " & i & "/" & 65535)
                Next
                'print clients that are open five by five
                Console.WriteLine("")
                Console.WriteLine("")
                If outputMethod = "1" Then
                    Console.WriteLine("Save to file")
                    Dim file As New System.IO.StreamWriter(filename)
                    For Each client In clients
                        file.WriteLine("Port: " & client.Client.RemoteEndPoint.ToString())
                    Next
                    file.Close()
                ElseIf outputMethod = "2" Then
                    If clients.Count > 0 Then
                        Console.WriteLine("Open ports:")
                        For i As Integer = 0 To clients.Count - 1 Step 5
                            Console.WriteLine("")
                            For j As Integer = i To i + 4
                                If j < clients.Count Then
                                    Console.Write("Port: " & clients(j).Client.RemoteEndPoint.ToString().Split(":"c)(1) & " | ")
                                End If
                            Next
                        Next
                    Else
                        Console.WriteLine("No open ports found")
                    End If
                End If
            Else
                'scan all ports on the network
                Dim thisIp As IPAddress = Net.IPAddress.Parse(ipToScan)
                Dim clients As New List(Of TcpClient)
                For i As Integer = 1 To 65535
                    Dim client As New TcpClient()
                    Try
                        Dim result As IAsyncResult = client.BeginConnect(thisIp.ToString(), i, Nothing, Nothing) 'try to connect to the port
                        Dim th As Threading.WaitHandle = result.AsyncWaitHandle
                        Try
                            If result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(1000), False) Then
                                If client.Connected Then
                                    clients.Add(client)
                                End If
                            End If
                        Catch ex As Exception
                            th.Close()
                        End Try
                        'add client to list
                    Catch ex As Exception
                        Debug.WriteLine(ex.Message)
                    End Try
                    'clear last line and print progress bar
                    Console.SetCursorPosition(0, Console.CursorTop - 1) 'move cursor to the beginning of the line
                    Console.Write(New String(" "c, Console.WindowWidth)) 'clear line
                    Console.SetCursorPosition(0, Console.CursorTop - 1) 'move cursor to the beginning of the line
                    'print progress bar
                    Console.WriteLine("[" & New String("="c, (i / 65535 * 100)) & New String(" "c, (100 - (i / 65535 * 100))) & "] " & i & "/" & 65535)
                Next
                'print clients that are open five by five
                Console.WriteLine("")
                Console.WriteLine("")
                If clients.Count > 0 Then
                    Console.WriteLine("Open ports:")
                    For i As Integer = 0 To clients.Count - 1 Step 5
                        Console.WriteLine("")
                        For j As Integer = i To i + 4
                            If j < clients.Count Then
                                Console.WriteLine("Port: " & clients(j).Client.RemoteEndPoint.ToString().Split(":"c)(1))
                            End If
                        Next
                    Next
                Else
                    Console.WriteLine("No open ports found")
                End If
            End If
        ElseIf method = "2" Then
            'scan specific ports
            Console.WriteLine("Enter the ports you want to scan:")
            Dim ports = Console.ReadLine()
            Dim portList = ports.Split(",")
            Dim thisIp As IPAddress = Net.IPAddress.Parse(ipToScan)
            Dim clients As New List(Of TcpClient)
            For Each port In portList
                Dim client As New TcpClient()
                Try
                    Dim result As IAsyncResult = client.BeginConnect(thisIp.ToString(), port, Nothing, Nothing) 'try to connect to the port
                    Dim th As Threading.WaitHandle = result.AsyncWaitHandle
                    Try
                        If result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(500), False) Then
                            If client.Connected Then
                                clients.Add(client)
                            End If
                        End If
                    Catch ex As Exception
                        th.Close()
                    End Try
                Catch ex As Exception
                    Debug.WriteLine(ex.Message)
                End Try
            Next
            'print clients that are open five by five
            Console.WriteLine("")
            Console.WriteLine("")
            If clients.Count > 0 Then
                Console.WriteLine("Open ports:")
                For i As Integer = 0 To clients.Count - 1 Step 5
                    Console.WriteLine("")
                    For j As Integer = i To i + 4
                        If j < clients.Count Then
                            Console.Write(clients(j).Client.RemoteEndPoint.ToString().Split(":"c)(1) & " | ")
                        End If
                    Next
                Next
            Else
                Console.WriteLine("No open ports found")
            End If
        End If
        Console.WriteLine("")
        Console.WriteLine("Press any key to return to menu")
        Console.ReadKey()
        'return to menu
        Main()
    End Function

    Function hostnameLookup()
        'clear console and print header
        Console.Clear()
        WriteHeader()
        Console.WriteLine("Hostname Lookup")
        Console.Write("Enter the ip you want to lookup: ")
        Dim ipToLookup = Console.ReadLine()
        Console.WriteLine("")
        Console.WriteLine("")
        'lookup hostname
        Try
            Dim hostname = Dns.GetHostEntry(ipToLookup).HostName
            Console.WriteLine("Hostname: " & hostname)
        Catch ex As Exception
            Console.WriteLine("Hostname not found")
        End Try
        Console.WriteLine("")
        Console.WriteLine("Press any key to return to menu")
        Console.ReadLine()
        'return to menu
        Main()
    End Function

    Function deviceScanner()
        'clear console and print header
        Console.Clear()
        WriteHeader()
        Console.WriteLine("Device Scanner")
        Console.Write("Enter the ip you want to scan: ")
        Dim ipToScan = Console.ReadLine()
        Console.WriteLine("")
        Console.WriteLine("")
        'scan all devices on the network
        Try
            Dim hostname = Dns.GetHostByAddress(ipToScan).HostName
            For Each hostAdr In Dns.GetHostEntry(hostname).AddressList()
                Console.WriteLine("Name: " & hostname & " IP Address: " & hostAdr.ToString())
            Next

        Catch
            Console.WriteLine("No device found")
        End Try
        Console.WriteLine("")
        Console.WriteLine("Press any key to return to menu")
        Console.ReadLine()
        'return to menu
        Main()
    End Function

    Function packetSniffer()
        Console.Clear()
        WriteHeader()
        Console.WriteLine("Packet sniffer")
        Console.WriteLine("")
        Console.Write("Enter the IP you want to sniff: ")
        Dim ip As IPAddress = IPAddress.Parse(Console.ReadLine())
        Console.WriteLine("")
        Console.WriteLine("Enter the port you want to sniff: ")
        Dim port As Integer = Console.ReadLine()
        Dim proxy As New ProxyRecorder(port, ip.Address, port)
        Dim data As String()
        Using proxy.Record("Sniffer")
            Dim client As New WebClient()
            client.Proxy = proxy.CreateHttpWebProxy()
            data.Append(client.DownloadString(String.Format("{0}:{1}", ip, port)))
        End Using
    End Function

    Private Sub OnNewPacket(ByVal m As Monitor, ByVal p As Packet) Handles packetmon.NewPacket
        Console.WriteLine(p.ToString())
    End Sub

    Public Function WriteHeader()
        Console.WriteLine(" _________  ___  ___  _______           ________  ________  ________  ________  ________  ________  _______      ")
        Console.WriteLine("|\___   ___\\  \|\  \|\  ___ \         |\   ____\|\   __  \|\   __  \|\   __  \|\   __  \|\   ____\|\  ___ \     ")
        Console.WriteLine("\|___ \  \_\ \  \\\  \ \   __/|        \ \  \___|\ \  \|\  \ \  \|\  \ \  \|\ /\ \  \|\  \ \  \___|\ \   __/|    ")
        Console.WriteLine("     \ \  \ \ \   __  \ \  \_|/__       \ \  \  __\ \   __  \ \   _  _\ \   __  \ \   __  \ \  \  __\ \  \_|/__  ")
        Console.WriteLine("      \ \  \ \ \  \ \  \ \  \_|\ \       \ \  \|\  \ \  \ \  \ \  \\  \\ \  \|\  \ \  \ \  \ \  \|\  \ \  \_|\ \ ")
        Console.WriteLine("       \ \__\ \ \__\ \__\ \_______\       \ \_______\ \__\ \__\ \__\\ _\\ \_______\ \__\ \__\ \_______\ \_______\")
        Console.WriteLine("        \|__|  \|__|\|__|\|_______|        \|_______|\|__|\|__|\|__|\|__|\|_______|\|__|\|__|\|_______|\|_______|")
        Console.WriteLine("")
        Console.WriteLine("")
    End Function

    Private Class ARPHelper
        Public Sub New()
        End Sub

        Friend Function GetMacAddress(ipAddress As IPAddress) As Object
            Dim macAddress As Object = Nothing
            Dim networkInterface As NetworkInterface = Nothing
            Dim networkInterfaceCollection As NetworkInterface() = NetworkInterface.GetAllNetworkInterfaces()
            For Each networkInterface In networkInterfaceCollection
                Dim unicastIPAddressInformationCollection As UnicastIPAddressInformationCollection = networkInterface.GetIPProperties().UnicastAddresses
                For Each unicastIPAddressInformation As UnicastIPAddressInformation In unicastIPAddressInformationCollection
                    If unicastIPAddressInformation.Address.AddressFamily = AddressFamily.InterNetwork Then
                        If unicastIPAddressInformation.Address.Equals(ipAddress) Then
                            macAddress = networkInterface.GetPhysicalAddress().ToString()
                            Exit For
                        End If
                    End If
                Next
            Next
            Return macAddress
        End Function
    End Class
End Module

Class IPEntry
    Property IP As String
    Property Hostname As String
    Property MAC As String
    Property OS As String
    Property Manufacturer As String
    Property Location As String
    Property DeviceType As String
    Property DeviceClass As String
    Property DeviceSubClass As String
    Property DeviceProtocol As String
    Property DevicePort As String
End Class