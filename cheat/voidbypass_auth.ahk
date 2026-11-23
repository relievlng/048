; ============================================================
; Void Bypass Auth Client - AHK v2
; Drop this file into your cheat folder and #Include it.
;
; Usage:
;   #Include 048_auth.ahk
;
;   ; On startup - exits the script on failure
;   g_client := AuthVoidBypass("https://your-service.railway.app", "your_internal_api_key")
;   g_client.Authenticate()   ; prompts for key, exits if invalid
;
;   ; Log events at any point
;   g_client.Event("inject")
;   g_client.Event("menu_open")
;   g_client.Event("menu_close")
;   g_client.Event("destruct")
;   g_client.Event("fac_reset_request", "user pressed FAC reset")
;   g_client.Event("custom", "anything you want to log")
; ============================================================

class AuthVoidBypass {

    ; ---- constructor --------------------------------------------------
    __New(baseUrl, apiKey := "") {
        this._base   := RTrim(baseUrl, "/")
        this._apiKey := apiKey
        this._key    := ""
        this._hwid   := this._GetHWID()
        this._ip     := this._GetPublicIP()
        this._sys    := this._GetSystemInfo()
        this.User    := Map()     ; populated after Authenticate()
    }

    ; ---- public: authenticate ----------------------------------------
    Authenticate(promptMsg := "Enter your license key:") {
        key := InputBox(promptMsg, "Void Bypass Auth", "w340 h120").Value
        if (key = "") {
            MsgBox("No key entered. Exiting.", "Void Bypass Auth", "Iconx")
            ExitApp
        }
        this._key := StrUpper(Trim(key))

        payload := Map(
            "key",     this._key,
            "hwid",    this._hwid,
            "api_key", this._apiKey,
            "ip",      this._ip,
            "system",  this._sys
        )

        resp := this._Post("/auth", payload)

        if (resp.Has("ok") && resp["ok"]) {
            this.User := resp
            if (resp.Has("hwid_bound") && resp["hwid_bound"])
                MsgBox("Machine registered to your license.", "Void Bypass Auth", "Iconi T2")
            return true
        }

        err := resp.Has("error") ? resp["error"] : "unknown"
        msgs := Map(
            "invalid_key",    "Invalid license key. Check the key and try again.",
            "banned",         "This license has been banned. Contact support.",
            "expired",        "This license has expired. Contact support to renew.",
            "hwid_mismatch",  "HWID mismatch. Contact support if you changed machines.",
            "inactive",       "This license is not active. Contact support.",
            "missing_fields", "Auth request malformed (client error).",
            "server_error",   "Server error. Try again or contact support."
        )
        msg := msgs.Has(err) ? msgs[err] : "Authentication failed: " . err
        MsgBox(msg, "Void Bypass - Failed", "Iconx")
        ExitApp
    }

    ; ---- public: log a cheat lifecycle event -------------------------
    Event(eventType, note := "") {
        if (this._key = "")
            return false

        payload := Map(
            "key",        this._key,
            "hwid",       this._hwid,
            "api_key",    this._apiKey,
            "event_type", eventType,
            "ip",         this._ip,
            "system",     this._sys,
            "note",       note
        )
        resp := this._Post("/event", payload, 4000)
        return (resp.Has("ok") && resp["ok"])
    }

    ; ---- HWID ----------------------------------------------------------
    _GetHWID() {
        parts := ""

        ; CPU ID
        try {
            wmi := ComObject("WbemScripting.SWbemLocator").ConnectServer()
            for item in wmi.ExecQuery("SELECT ProcessorId FROM Win32_Processor")
                parts .= item.ProcessorId . "|"
        }

        ; Disk serial
        try {
            wmi2 := ComObject("WbemScripting.SWbemLocator").ConnectServer()
            for item in wmi2.ExecQuery("SELECT SerialNumber FROM Win32_DiskDrive")
                parts .= item.SerialNumber . "|"
        }

        ; Motherboard serial
        try {
            wmi3 := ComObject("WbemScripting.SWbemLocator").ConnectServer()
            for item in wmi3.ExecQuery("SELECT SerialNumber FROM Win32_BaseBoard")
                parts .= item.SerialNumber . "|"
        }

        ; Machine name fallback
        parts .= EnvGet("COMPUTERNAME") . "|" . EnvGet("USERNAME")

        return SubStr(this._SHA256Hex(parts), 1, 64)
    }

    ; ---- system info --------------------------------------------------
    _GetSystemInfo() {
        info := Map()

        ; OS name + build
        try {
            info["os"] := EnvGet("OS") = "Windows_NT"
                ? "Windows " . this._RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion")
                : "Windows"
            info["build"] := this._RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild")
        }

        ; CPU name
        try {
            info["cpu"] := SubStr(
                this._RegRead("HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString"),
                1, 80)
        }

        ; RAM (GlobalMemoryStatusEx)
        try {
            ; MEMORYSTATUSEX: dwLength(4) dwMemoryLoad(4) ullTotalPhys(8) ... = 64 bytes
            buf := Buffer(64, 0)
            NumPut("UInt", 64, buf, 0)   ; dwLength
            DllCall("GlobalMemoryStatusEx", "Ptr", buf)
            totalPhys := NumGet(buf, 8, "UInt64")
            info["ram"] := Round(totalPhys / (1024 ** 3), 1) . " GB"
        }

        ; Screen resolution
        try {
            info["screen"] := DllCall("GetSystemMetrics", "Int", 0, "Int") . "x"
                            . DllCall("GetSystemMetrics", "Int", 1, "Int")
        }

        ; Locale
        try {
            lcid := DllCall("GetUserDefaultLCID", "UInt")
            nameBuf := Buffer(85, 0)
            DllCall("LCIDToLocaleName", "UInt", lcid, "Ptr", nameBuf, "Int", 85, "UInt", 0)
            info["locale"] := StrGet(nameBuf)
        }

        ; Hostname
        info["hostname"] := SubStr(EnvGet("COMPUTERNAME"), 1, 64)

        return info
    }

    ; ---- public IP ----------------------------------------------------
    _GetPublicIP() {
        try {
            whr := ComObject("WinHttp.WinHttpRequest.5.1")
            whr.Open("GET", "https://api4.my-ip.io/v2/ip.txt", false)
            whr.SetTimeouts(4000, 4000, 4000, 4000)
            whr.Send()
            return Trim(whr.ResponseText)
        }
        try {
            whr2 := ComObject("WinHttp.WinHttpRequest.5.1")
            whr2.Open("GET", "https://checkip.amazonaws.com", false)
            whr2.SetTimeouts(4000, 4000, 4000, 4000)
            whr2.Send()
            return Trim(whr2.ResponseText)
        }
        return ""
    }

    ; ---- HTTP POST (WinHttp, synchronous) ----------------------------
    _Post(path, payload, timeoutMs := 8000) {
        try {
            body := this._MapToJSON(payload)
            whr  := ComObject("WinHttp.WinHttpRequest.5.1")
            whr.Open("POST", this._base . path, false)
            whr.SetTimeouts(timeoutMs, timeoutMs, timeoutMs, timeoutMs)
            whr.SetRequestHeader("Content-Type", "application/json")
            whr.Send(body)
            return this._ParseJSON(whr.ResponseText)
        } catch as e {
            return Map("ok", false, "error", "connection_failed: " . e.Message)
        }
    }

    ; ---- minimal JSON serialiser (Map/primitive only) ----------------
    _MapToJSON(val) {
        if IsObject(val) && val is Map {
            parts := []
            for k, v in val
                parts.Push('"' . k . '":' . this._MapToJSON(v))
            return "{" . this._Join(parts, ",") . "}"
        }
        if IsObject(val) && val is Array {
            parts := []
            for item in val
                parts.Push(this._MapToJSON(item))
            return "[" . this._Join(parts, ",") . "]"
        }
        if (val = true)  return "true"
        if (val = false) return "false"
        if (val = "")    return "null"
        if IsNumber(val) return val
        ; string - escape backslash and double-quote
        escaped := StrReplace(StrReplace(String(val), "\", "\\"), '"', '\"')
        return '"' . escaped . '"'
    }

    ; ---- minimal JSON parser (enough for server responses) -----------
    _ParseJSON(text) {
        result := Map()
        text := Trim(text)
        if (SubStr(text, 1, 1) != "{")
            return result

        ; Strip braces
        inner := SubStr(text, 2, StrLen(text) - 2)

        ; Tokenise key:value pairs (handles strings, booleans, numbers, null)
        pos := 1
        while (pos <= StrLen(inner)) {
            ; Skip whitespace and commas
            while (pos <= StrLen(inner) && InStr(" ,`t`n`r", SubStr(inner, pos, 1)))
                pos++
            if (pos > StrLen(inner))
                break

            ; Key (must be a quoted string)
            if (SubStr(inner, pos, 1) != '"')
                break
            pos++
            keyStart := pos
            while (pos <= StrLen(inner) && SubStr(inner, pos, 1) != '"')
                pos++
            key := SubStr(inner, keyStart, pos - keyStart)
            pos += 2  ; skip closing " and :

            ; Skip whitespace
            while (pos <= StrLen(inner) && InStr(" `t", SubStr(inner, pos, 1)))
                pos++

            ; Value
            ch := SubStr(inner, pos, 1)
            if (ch = '"') {
                pos++
                valStart := pos
                while (pos <= StrLen(inner) && SubStr(inner, pos, 1) != '"')
                    pos++
                result[key] := SubStr(inner, valStart, pos - valStart)
                pos++
            } else if (SubStr(inner, pos, 4) = "true") {
                result[key] := true
                pos += 4
            } else if (SubStr(inner, pos, 5) = "false") {
                result[key] := false
                pos += 5
            } else if (SubStr(inner, pos, 4) = "null") {
                result[key] := ""
                pos += 4
            } else {
                ; Number
                numStart := pos
                while (pos <= StrLen(inner) && InStr("0123456789.-", SubStr(inner, pos, 1)))
                    pos++
                result[key] := SubStr(inner, numStart, pos - numStart) + 0
            }
        }
        return result
    }

    ; ---- SHA-256 via CNG (stdlib, no external deps) ------------------
    _SHA256Hex(text) {
        hAlg := 0
        hHash := 0
        try {
            if DllCall("bcrypt\BCryptOpenAlgorithmProvider", "Ptr*", &hAlg, "Str", "SHA256", "Ptr", 0, "UInt", 0)
                return "00000000000000000000000000000000"
            cbHash := 0
            cbData := 0
            DllCall("bcrypt\BCryptGetProperty", "Ptr", hAlg, "Str", "HashDigestLength",
                "UInt*", &cbHash, "UInt", 4, "UInt*", &cbData, "UInt", 0)
            if DllCall("bcrypt\BCryptCreateHash", "Ptr", hAlg, "Ptr*", &hHash,
                "Ptr", 0, "UInt", 0, "Ptr", 0, "UInt", 0, "UInt", 0)
                return "00000000000000000000000000000000"
            encoded := Buffer(StrPut(text, "UTF-8"), 0)
            StrPut(text, encoded, "UTF-8")
            DllCall("bcrypt\BCryptHashData", "Ptr", hHash, "Ptr", encoded, "UInt", encoded.Size - 1, "UInt", 0)
            hashBuf := Buffer(cbHash, 0)
            DllCall("bcrypt\BCryptFinishHash", "Ptr", hHash, "Ptr", hashBuf, "UInt", cbHash, "UInt", 0)
            hex := ""
            loop cbHash
                hex .= Format("{:02x}", NumGet(hashBuf, A_Index - 1, "UChar"))
            return hex
        } finally {
            if hHash
                DllCall("bcrypt\BCryptDestroyHash", "Ptr", hHash)
            if hAlg
                DllCall("bcrypt\BCryptCloseAlgorithmProvider", "Ptr", hAlg, "UInt", 0)
        }
    }

    ; ---- registry read helper ----------------------------------------
    _RegRead(key, val) {
        try return RegRead(key, val)
        return ""
    }

    ; ---- array join --------------------------------------------------
    _Join(arr, sep) {
        out := ""
        for i, v in arr
            out .= (i > 1 ? sep : "") . v
        return out
    }
}
