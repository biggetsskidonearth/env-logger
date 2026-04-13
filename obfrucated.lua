--[[
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                           ENV LOGGER v5.0.0                                 ║
    ║                Enterprise-Grade Runtime Deobfuscation Engine                ║
    ║                                                                             ║
    ║  Features:                                                                  ║
    ║    • Full environment proxy interception with multi-layer anti-detection    ║
    ║    • Advanced VM deobfuscation (bytecode-level reconstruction)              ║
    ║    • URL/link deobfuscation with recursive script chain tracing             ║
    ║    • Discord webhook output with chunked delivery                           ║
    ║    • createfile() output to executor workspace folder                       ║
    ║    • 500K operation log capacity                                            ║
    ║    • Deep closure/upvalue/constant/proto analysis                           ║
    ║    • Namecall + metatable hooking for complete Roblox interception          ║
    ║    • Anti-tamper: prevents obfuscated code from detecting or unhooking      ║
    ║    • VM pattern detection: identifies and traces virtual machine loops      ║
    ║    • Opcode pattern matching for Lua VM reconstructors                      ║
    ║    • Automatic string deobfuscation (char codes, xor, base64, etc.)        ║
    ║    • Registry/GC scanning for hidden closures and tables                   ║
    ║                                                                             ║
    ║  Supports: Luraph, Prometheus, IronBrew2, Moonsec, PSU, Aztupbrew,         ║
    ║            Synapse Xen, WeAreDevs, Bytecode VMs, custom VMs, and more      ║
    ║                                                                             ║
    ║  Requirements: Strong executor (Synapse X, Script-Ware, Fluxus, etc.)      ║
    ║  Usage:                                                                     ║
    ║    local EnvLogger = loadstring(RAWFILE)()                                  ║
    ║    local obfCode   = loadstring(RAWFILE)()                                  ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
--]]

-- ============================================================================
-- STAGE 0: PRESERVED ORIGINALS
-- Must be captured FIRST before any hooking can occur.
-- Every original reference we might need is saved here.
-- ============================================================================

local _rawget           = rawget
local _rawset           = rawset
local _rawequal         = rawequal
local _rawlen           = rawlen
local _type             = type
local _typeof           = typeof or type
local _tostring         = tostring
local _tonumber         = tonumber
local _pairs            = pairs
local _ipairs           = ipairs
local _next             = next
local _select           = select
local _unpack           = unpack or table.unpack
local _pcall            = pcall
local _xpcall           = xpcall
local _error            = error
local _assert           = assert
local _setmetatable     = setmetatable
local _getmetatable     = getmetatable
local _setfenv          = setfenv
local _getfenv          = getfenv
local _newproxy         = newproxy
local _print            = print
local _warn             = warn or print
local _tick             = tick or os.clock
local _os_clock         = os and os.clock or _tick
local _task_wait        = task and task.wait or wait
local _task_spawn       = task and task.spawn or spawn
local _task_defer       = task and task.defer or defer or spawn
local _task_delay       = task and task.delay or delay
local _coroutine_wrap   = coroutine.wrap
local _coroutine_yield  = coroutine.yield

local _pack = table.pack or function(...)
    return { n = _select("#", ...), ... }
end

-- Deep-copy all standard libraries so hooks can't affect our internals
local function _deepCopyLib(lib)
    local copy = {}
    for k, v in _pairs(lib) do copy[k] = v end
    return copy
end

local _string     = _deepCopyLib(string)
local _table      = _deepCopyLib(table)
local _math       = _deepCopyLib(math)
local _coroutine  = _deepCopyLib(coroutine)
local _bit        = bit and _deepCopyLib(bit) or bit32 and _deepCopyLib(bit32) or nil
local _debug      = debug and _deepCopyLib(debug) or {}

-- Executor-specific function captures
local _loadstring           = loadstring or load
local _writefile            = writefile
local _readfile             = readfile
local _appendfile           = appendfile
local _isfile               = isfile
local _makefolder           = makefolder
local _isfolder             = isfolder
local _delfile              = delfile
local _listfiles            = listfiles

-- HTTP
local _httpget = _pcall(function() return game.HttpGet end) and function(url)
    return game:HttpGet(url)
end or nil
local _httppost = _pcall(function() return game.HttpPost end) and function(url, body, ct)
    return game:HttpPost(url, body, ct)
end or nil
local _syn_request    = syn and syn.request or nil
local _http_request   = http_request or (http and http.request) or nil
local _request        = request or _syn_request or _http_request or nil
local _HttpService    = (_pcall(function() return game:GetService("HttpService") end))
    and game:GetService("HttpService") or nil

-- Debug / Executor APIs
local _getinfo            = _debug.getinfo or (debug and debug.getinfo)
local _getupvalue         = _debug.getupvalue or (debug and debug.getupvalue)
local _setupvalue         = _debug.setupvalue or (debug and debug.setupvalue)
local _getconstants       = (debug and debug.getconstants) or getconstants
local _setconstant        = (debug and debug.setconstant) or setconstant
local _getupvalues        = (debug and debug.getupvalues) or getupvalues
local _setupvalues        = (debug and debug.setupvalues) or setupvalues
local _getprotos          = (debug and debug.getprotos) or getprotos
local _getstack           = (debug and debug.getstack) or getstack
local _setstack           = (debug and debug.setstack) or setstack
local _hookfunction       = hookfunction or replaceclosure
local _newcclosure        = newcclosure
local _checkcaller        = checkcaller
local _islclosure         = islclosure
local _iscclosure         = iscclosure
local _getnamecallmethod  = getnamecallmethod
local _setnamecallmethod  = setnamecallmethod
local _getrawmetatable    = getrawmetatable
local _setreadonly        = setreadonly
local _isreadonly         = isreadonly
local _cloneref           = cloneref
local _compareinstances   = compareinstances
local _gethiddenproperty  = gethiddenproperty
local _sethiddenproperty  = sethiddenproperty
local _firesignal         = firesignal
local _fireclickdetector  = fireclickdetector
local _fireproximityprompt = fireproximityprompt
local _decompile          = decompile
local _getgenv            = getgenv
local _getrenv            = getrenv
local _getreg             = getreg
local _getgc              = getgc
local _getinstances       = getinstances
local _getnilinstances    = getnilinstances
local _getscripts         = getscripts
local _getrunningscripts  = getrunningscripts
local _getloadedmodules   = getloadedmodules
local _getconnections     = getconnections
local _getcallingscript   = getcallingscript
local _checkclosure       = checkclosure
local _isexecutorclosure  = isexecutorclosure or is_synapse_function or checkclosure
local _identifyexecutor   = identifyexecutor
local _setclipboard       = setclipboard or toclipboard
local _getclipboard       = getclipboard

-- createfile — the primary file output method
-- Falls back to writefile if createfile doesn't exist
local _createfile = createfile or _writefile

-- ============================================================================
-- STAGE 1: CONFIGURATION
-- ============================================================================

local Config = {
    -- Capacity
    MaxLogEntries              = 500000,
    MaxRecursionDepth          = 100,
    MaxTableSerializeDepth     = 8,
    MaxStringLength            = 10000,
    MaxUrlFetchSize            = 5 * 1024 * 1024,
    MaxGCScanObjects           = 5000,
    MaxVMIterations            = 1000000,

    -- Core behavior
    PrintLive                  = false,
    PrintLiveFilter            = nil,       -- nil = all, or table of opcodes
    CaptureStackTraces         = true,
    InferVariableNames         = true,
    CollapseChains             = true,
    SimplifyExpressions        = true,
    TrackControlFlow           = true,
    CaptureReturnValues        = true,
    CaptureClosureUpvalues     = true,
    CaptureDebugInfo           = true,
    TrackTableMutations        = true,
    DeobfuscateStrings         = true,
    DetectVMPatterns           = true,

    -- URL / Network
    DeobfuscateUrls            = true,
    RecursiveTrace             = true,
    MaxUrlRecursionDepth       = 15,
    FollowRedirects            = true,

    -- Hook flags
    HookGlobalEnv              = true,
    HookMetatables             = true,
    HookStringLib              = true,
    HookMathLib                = true,
    HookTableLib               = true,
    HookCoroutines             = true,
    HookRequire                = true,
    HookGetfenv                = true,
    HookLoadstring             = true,
    HookHttpRequests           = true,
    HookNamecall               = true,
    HookDebugLib               = true,
    HookGarbageCollector       = true,
    HookClipboard              = true,
    HookBitLib                 = true,
    HookFireSignal             = true,
    HookSpawn                  = true,
    HookDelay                  = true,

    -- Anti-detection
    SpoofEnvironment           = true,
    HideFromGetfenv            = true,
    PreventUnhooking           = true,
    SpoofCallerCheck           = true,
    SpoofTypeChecks            = true,
    BlockDebugAccess           = true,
    MimicOriginalErrors        = true,

    -- VM Deobfuscation
    VM = {
        Enabled                = true,
        TraceVMLoops           = true,
        CaptureVMStack         = true,
        CaptureVMRegisters     = true,
        ReconstructOpcodes     = true,
        IdentifyObfuscator     = true,
        MaxOpcodeCapture       = 50000,
        DetectStringDecrypt    = true,
        TraceTableConstructs   = true,
        FollowClosureChains    = true,
    },

    -- Webhook
    Webhook = {
        Enabled        = true,
        Url            = "https://discord.com/api/webhooks/1493309004456395023/q129qkY_tAUCYJQ4v39eZCKVkXGCyonm9N4BiHNz3HEOMpccjZou6ey4obJkP2U4885X",
        ChunkSize      = 1900,
        Username       = "Env Logger v5.0",
        AvatarUrl      = "",
        SendSummary    = true,
        SendSource     = true,
        SendLog        = true,
        SendRemotes    = true,
        SendUrls       = true,
        SendVMAnalysis = true,
        RateLimitMs    = 1100,
        Color          = {
            Info    = 3447003,
            Success = 3066993,
            Warning = 15844367,
            Error   = 15158332,
            VM      = 10181046,
        },
    },

    -- File output (createfile -> workspace folder)
    Output = {
        Enabled           = true,
        Folder            = "EnvLogger",
        AutoSave          = true,
        AutoSaveInterval  = 15,
        CreateSubfolders  = true,
        TimestampFiles    = true,
        SaveReconstructed = true,
        SaveOperationLog  = true,
        SaveSummary       = true,
        SaveRemotes       = true,
        SaveUrls          = true,
        SaveVMAnalysis    = true,
        SaveClosures      = true,
        SaveRawLog        = true,
    },

    -- Platform (auto-detected)
    IsRoblox       = _pcall(function() return game end),
    HasFileSystem  = _createfile ~= nil,
    HasRequest     = _request ~= nil,
    HasDebug       = _getinfo ~= nil,
    HasGC          = _getgc ~= nil,
    HasHookFunc    = _hookfunction ~= nil,
    HasNewCClosure = _newcclosure ~= nil,
    ExecutorName   = (_identifyexecutor and (function()
        local ok, name = _pcall(_identifyexecutor)
        return ok and name or "Unknown"
    end)()) or "Unknown",
}

-- ============================================================================
-- STAGE 2: OPCODES
-- ============================================================================

local OpCodes = {
    -- Core
    CALL            = "CALL",
    INDEX           = "INDEX",
    NEWINDEX        = "NEWINDEX",
    NAMECALL        = "NAMECALL",
    CONCAT          = "CONCAT",
    ARITH           = "ARITH",
    COMPARE         = "COMPARE",
    LEN             = "LEN",
    UNARY           = "UNARY",
    ITERATOR        = "ITERATOR",

    -- Environment
    GETFENV         = "GETFENV",
    SETFENV         = "SETFENV",
    REQUIRE         = "REQUIRE",
    METATABLE       = "METATABLE",
    TOSTRING        = "TOSTRING",
    TONUMBER        = "TONUMBER",
    RAWOP           = "RAWOP",

    -- Code
    ASSIGNMENT      = "ASSIGNMENT",
    CONDITION       = "CONDITION",
    RETURN          = "RETURN",
    CLOSURE         = "CLOSURE",
    LOADSTRING      = "LOADSTRING",

    -- Network
    HTTP_FETCH      = "HTTP_FETCH",
    HTTP_SEND       = "HTTP_SEND",
    DEOBF_URL       = "DEOBF_URL",
    REMOTE_FIRE     = "REMOTE_FIRE",
    REMOTE_INVOKE   = "REMOTE_INVOKE",

    -- Analysis
    UPVALUE         = "UPVALUE",
    CONSTANT        = "CONSTANT",
    PROTO           = "PROTO",
    STACK           = "STACK",
    GC_SCAN         = "GC_SCAN",
    CLIPBOARD       = "CLIPBOARD",
    ERROR_CAUGHT    = "ERROR_CAUGHT",
    COROUTINE_OP    = "COROUTINE_OP",

    -- VM Deobfuscation
    VM_LOOP         = "VM_LOOP",
    VM_OPCODE       = "VM_OPCODE",
    VM_STACK_OP     = "VM_STACK_OP",
    VM_REGISTER     = "VM_REGISTER",
    VM_JUMP         = "VM_JUMP",
    VM_STRING_DECRYPT = "VM_STRING_DECRYPT",
    VM_TABLE_BUILD  = "VM_TABLE_BUILD",
    VM_CLOSURE_CREATE = "VM_CLOSURE_CREATE",
    VM_IDENTIFIED   = "VM_IDENTIFIED",

    -- Meta
    COMMENT         = "COMMENT",
    HOOKDETECT      = "HOOKDETECT",
    ANTI_TAMPER     = "ANTI_TAMPER",
    BLOCKED         = "BLOCKED",
}

-- ============================================================================
-- STAGE 3: OPERATION LOG
-- ============================================================================

local Log = {
    entries             = {},
    count               = 0,
    startTime           = _os_clock(),
    idCounter           = 0,

    -- Categorized data
    urlsDiscovered      = {},
    scriptsLoaded       = {},
    errorsLogged        = {},
    remotesCaptured     = {},
    closureMap          = {},
    upvalueMap          = {},
    stringsDecrypted    = {},
    vmOpcodes           = {},
    vmIdentification    = {},
    tableMutations      = {},
    blockedOperations   = {},
    hookDetections      = {},
}

function Log.nextId()
    Log.idCounter = Log.idCounter + 1
    return Log.idCounter
end

function Log.record(opcode, data)
    if Log.count >= Config.MaxLogEntries then return end

    Log.count    = Log.count + 1
    data.op      = opcode
    data.seq     = Log.count
    data.time    = _os_clock() - Log.startTime

    if Config.CaptureStackTraces and _debug.traceback then
        local ok, stack = _pcall(_debug.traceback, "", 3)
        if ok then data.stack = stack end
    end

    Log.entries[Log.count] = data

    if Config.PrintLive then
        if not Config.PrintLiveFilter or Config.PrintLiveFilter[opcode] then
            _print(_string.format("[%06d|%.3fs] %s", Log.count, data.time, Serializer.opToString(data)))
        end
    end
end

-- ============================================================================
-- STAGE 4: SERIALIZER
-- ============================================================================

local Serializer = {}

local _objectNames    = {}
local _objectIds      = {}
local _nameCounters   = {}
local _cycleTracker   = {}

function Serializer.nameOf(obj, hint)
    if _objectNames[obj] then return _objectNames[obj] end
    local t = _type(obj)
    if t == "string" then return Serializer.serializeString(obj) end
    if t == "number" or t == "boolean" or t == "nil" then return _tostring(obj) end

    local prefix = hint or t
    _nameCounters[prefix] = (_nameCounters[prefix] or 0) + 1
    local name
    if _nameCounters[prefix] == 1 then
        name = prefix
    else
        name = prefix .. "_" .. _nameCounters[prefix]
    end

    _objectNames[obj] = name
    _objectIds[obj]   = Log.nextId()
    return name
end

function Serializer.serializeString(s)
    if _type(s) ~= "string" then return _tostring(s) end
    local len = #s
    if len > Config.MaxStringLength then
        s = _string.sub(s, 1, Config.MaxStringLength)
        s = s .. "...(" .. len .. " total chars)"
    end
    s = _string.gsub(s, "\\", "\\\\")
    s = _string.gsub(s, "\"", "\\\"")
    s = _string.gsub(s, "\n", "\\n")
    s = _string.gsub(s, "\r", "\\r")
    s = _string.gsub(s, "\t", "\\t")
    s = _string.gsub(s, "\0", "\\0")
    s = _string.gsub(s, "[%c]", function(c)
        return _string.format("\\x%02X", _string.byte(c))
    end)
    return '"' .. s .. '"'
end

function Serializer.serialize(value, depth)
    depth = depth or 0
    if depth > Config.MaxTableSerializeDepth then return "..." end

    local t = _type(value)

    if t == "nil" then return "nil"
    elseif t == "boolean" then return _tostring(value)
    elseif t == "number" then
        if value ~= value then return "0/0" end
        if value == _math.huge then return "math.huge" end
        if value == -_math.huge then return "-math.huge" end
        if value == _math.floor(value) and _math.abs(value) < 2^53 then
            return _string.format("%d", value)
        end
        return _string.format("%.14g", value)
    elseif t == "string" then
        return Serializer.serializeString(value)
    elseif t == "function" then
        local name = Serializer.nameOf(value, "func")
        if Config.CaptureDebugInfo and _getinfo then
            local ok, info = _pcall(_getinfo, value)
            if ok and info then
                local src  = info.source or info.short_src or "?"
                local line = info.linedefined or "?"
                return _string.format("%s --[[%s:%s]]", name, src, line)
            end
        end
        return name
    elseif t == "table" then
        return Serializer.serializeTable(value, depth)
    elseif t == "userdata" then
        if Config.IsRoblox then return Serializer.serializeRoblox(value) end
        return Serializer.nameOf(value, "userdata")
    elseif t == "thread" then
        return Serializer.nameOf(value, "thread")
    else
        local ok, str = _pcall(_tostring, value)
        return ok and str or ("<?:" .. t .. ">")
    end
end

function Serializer.serializeTable(tbl, depth)
    if depth > Config.MaxTableSerializeDepth then return "{--[[deep]]}" end
    if _cycleTracker[tbl] then
        return (_objectNames[tbl] or "tbl") .. " --[[circular]]"
    end
    _cycleTracker[tbl] = true

    if _objectNames[tbl] and depth > 0 then
        _cycleTracker[tbl] = nil
        return _objectNames[tbl]
    end

    local parts    = {}
    local arrayLen = (_rawlen and _rawlen(tbl)) or #tbl
    local count    = 0
    local maxE     = 150

    for i = 1, arrayLen do
        if count >= maxE then
            _table.insert(parts, _string.format("... +%d more", arrayLen - count))
            break
        end
        local ok, v = _pcall(_rawget, tbl, i)
        if ok then
            _table.insert(parts, Serializer.serialize(v, depth + 1))
        else
            _table.insert(parts, "<?err>")
        end
        count = count + 1
    end

    local ok2, _ = _pcall(function()
        for k, v in _next, tbl do
            if _type(k) ~= "number" or k < 1 or k > arrayLen or k ~= _math.floor(k) then
                if count >= maxE then
                    _table.insert(parts, "...")
                    return
                end
                local keyStr
                if _type(k) == "string" and _string.match(k, "^[%a_][%w_]*$") then
                    keyStr = k
                else
                    keyStr = "[" .. Serializer.serialize(k, depth + 1) .. "]"
                end
                _table.insert(parts, keyStr .. " = " .. Serializer.serialize(v, depth + 1))
                count = count + 1
            end
        end
    end)

    _cycleTracker[tbl] = nil
    if #parts == 0 then return "{}" end

    local inner = _table.concat(parts, ", ")
    if #inner > 300 then
        local indent  = _string.rep("    ", depth + 1)
        local closing = _string.rep("    ", depth)
        return "{\n" .. indent .. _table.concat(parts, ",\n" .. indent) .. "\n" .. closing .. "}"
    end
    return "{" .. inner .. "}"
end

function Serializer.serializeRoblox(value)
    local ok, t = _pcall(_typeof, value)
    if not ok then return "<?roblox?>" end
    local ok2, str = _pcall(_tostring, value)
    if not ok2 then str = "<?>" end

    local serializers = {
        Instance = function()
            local ok3, path = _pcall(function() return value:GetFullName() end)
            local ok4, cls  = _pcall(function() return value.ClassName end)
            return (ok3 and path or str) .. " --[[" .. (ok4 and cls or "?") .. "]]"
        end,
        Vector3 = function()
            return _string.format("Vector3.new(%.6g, %.6g, %.6g)", value.X, value.Y, value.Z)
        end,
        Vector2 = function()
            return _string.format("Vector2.new(%.6g, %.6g)", value.X, value.Y)
        end,
        CFrame = function()
            local c = { value:GetComponents() }
            local p = {}
            for _, v in _ipairs(c) do _table.insert(p, _string.format("%.6g", v)) end
            return "CFrame.new(" .. _table.concat(p, ", ") .. ")"
        end,
        Color3 = function()
            return _string.format("Color3.new(%.4f, %.4f, %.4f)", value.R, value.G, value.B)
        end,
        UDim2 = function()
            return _string.format("UDim2.new(%.4f, %d, %.4f, %d)",
                value.X.Scale, value.X.Offset, value.Y.Scale, value.Y.Offset)
        end,
        UDim = function()
            return _string.format("UDim.new(%.4f, %d)", value.Scale, value.Offset)
        end,
        BrickColor = function()
            return _string.format('BrickColor.new("%s")', str)
        end,
        EnumItem = function() return _tostring(value) end,
        Rect = function()
            return _string.format("Rect.new(%.2f, %.2f, %.2f, %.2f)",
                value.Min.X, value.Min.Y, value.Max.X, value.Max.Y)
        end,
        NumberRange = function()
            return _string.format("NumberRange.new(%.4f, %.4f)", value.Min, value.Max)
        end,
        NumberSequence = function()
            return _string.format("NumberSequence(%s)", str)
        end,
        ColorSequence = function()
            return _string.format("ColorSequence(%s)", str)
        end,
        Ray = function()
            return _string.format("Ray.new(%s, %s)",
                Serializer.serialize(value.Origin, 1),
                Serializer.serialize(value.Direction, 1))
        end,
        Region3 = function() return "Region3(" .. str .. ")" end,
        TweenInfo = function() return "TweenInfo(" .. str .. ")" end,
    }

    local s = serializers[t]
    if s then
        local ok3, result = _pcall(s)
        if ok3 then return result end
    end
    return _string.format("%s(%s)", t, str)
end

function Serializer.serializeArgs(args, count)
    local parts = {}
    for i = 1, (count or 0) do
        _table.insert(parts, Serializer.serialize(args[i]))
    end
    return _table.concat(parts, ", ")
end

function Serializer.opToString(entry)
    local op = entry.op
    if not op then return "???" end

    if op == OpCodes.CALL then
        local fn   = Serializer.serialize(entry.func)
        local args = Serializer.serializeArgs(entry.args or {}, entry.argc or 0)
        local ret  = ""
        if entry.retc and entry.retc > 0 then
            ret = " -> " .. Serializer.serializeArgs(entry.rets or {}, entry.retc)
        end
        if entry.err then
            ret = " !! " .. _tostring(entry.err)
        end
        return _string.format("%s(%s)%s", fn, args, ret)

    elseif op == OpCodes.INDEX then
        return _string.format("%s[%s] => %s",
            Serializer.serialize(entry.target),
            Serializer.serialize(entry.key),
            Serializer.serialize(entry.value))

    elseif op == OpCodes.NEWINDEX then
        return _string.format("%s[%s] = %s",
            Serializer.serialize(entry.target),
            Serializer.serialize(entry.key),
            Serializer.serialize(entry.value))

    elseif op == OpCodes.NAMECALL then
        local args = Serializer.serializeArgs(entry.args or {}, entry.argc or 0)
        local ret = ""
        if entry.retc and entry.retc > 0 then
            ret = " -> " .. Serializer.serializeArgs(entry.rets or {}, entry.retc)
        end
        return _string.format("%s:%s(%s)%s",
            Serializer.serialize(entry.target),
            entry.method or "?", args, ret)

    elseif op == OpCodes.REMOTE_FIRE or op == OpCodes.REMOTE_INVOKE then
        local args = Serializer.serializeArgs(entry.args or {}, entry.argc or 0)
        return _string.format("[REMOTE] %s:%s(%s)",
            _tostring(entry.path or entry.name or "?"),
            entry.method or "?", args)

    elseif op == OpCodes.HTTP_FETCH then
        return _string.format("HTTP %s %s (status:%s size:%s)",
            _tostring(entry.httpMethod or "GET"),
            Serializer.serialize(entry.url),
            _tostring(entry.status or "?"),
            _tostring(entry.size or "?"))

    elseif op == OpCodes.LOADSTRING then
        local preview = entry.code and _string.sub(_tostring(entry.code), 1, 150) or "?"
        return _string.format("LOADSTRING (%d bytes) %s",
            entry.codeLength or 0, Serializer.serializeString(preview))

    elseif op == OpCodes.DEOBF_URL then
        return _string.format("DEOBF_URL %s => %d bytes",
            Serializer.serialize(entry.url), entry.size or 0)

    elseif op == OpCodes.VM_OPCODE then
        return _string.format("VM_OP [%s] A=%s B=%s C=%s",
            _tostring(entry.opname or entry.opcode or "?"),
            _tostring(entry.A or ""), _tostring(entry.B or ""), _tostring(entry.C or ""))

    elseif op == OpCodes.VM_IDENTIFIED then
        return _string.format("VM_IDENTIFIED: %s (confidence: %d%%)",
            _tostring(entry.obfuscator or "?"), entry.confidence or 0)

    elseif op == OpCodes.VM_STRING_DECRYPT then
        return _string.format("VM_DECRYPT: %s => %s",
            Serializer.serialize(entry.encrypted), Serializer.serialize(entry.decrypted))

    elseif op == OpCodes.UPVALUE then
        return _string.format("UPVALUE [%s] #%d = %s",
            _tostring(entry.funcName or "?"), entry.index or 0, Serializer.serialize(entry.value))

    elseif op == OpCodes.CONSTANT then
        return _string.format("CONST [%s] #%d = %s",
            _tostring(entry.funcName or "?"), entry.index or 0, Serializer.serialize(entry.value))

    elseif op == OpCodes.COMMENT then
        return "-- " .. (entry.text or "")

    elseif op == OpCodes.BLOCKED then
        return "BLOCKED: " .. (entry.text or entry.action or "?")

    else
        local parts = { op }
        for k, v in _pairs(entry) do
            if k ~= "op" and k ~= "seq" and k ~= "time" and k ~= "stack" then
                _table.insert(parts, k .. "=" .. Serializer.serialize(v))
            end
        end
        return _table.concat(parts, " ")
    end
end

-- ============================================================================
-- STAGE 5: PROXY FACTORY
-- ============================================================================

local Proxy = {}

local _proxyToReal  = {}
local _realToProxy  = {}
local _wrappedFuncs = {}
local _proxyCount   = 0

function Proxy.isProxy(v) return _proxyToReal[v] ~= nil end
function Proxy.unwrap(v)  return _proxyToReal[v] or v end

function Proxy.unwrapArgs(args, n)
    local u = {}
    for i = 1, n do u[i] = Proxy.unwrap(args[i]) end
    u.n = n
    return u
end

function Proxy.unwrapDeep(v)
    v = Proxy.unwrap(v)
    if _type(v) == "table" and not _cycleTracker[v] then
        _cycleTracker[v] = true
        local t = {}
        for k, val in _pairs(v) do
            t[Proxy.unwrapDeep(k)] = Proxy.unwrapDeep(val)
        end
        _cycleTracker[v] = nil
        return t
    end
    return v
end

function Proxy.wrapFunction(fn, name)
    if _wrappedFuncs[fn] then return _wrappedFuncs[fn] end
    _objectNames[fn] = name

    local wrapped = function(...)
        local args      = _pack(...)
        local unwrapped = Proxy.unwrapArgs(args, args.n)
        local results   = _pack(_pcall(fn, _unpack(unwrapped, 1, unwrapped.n)))
        local success   = results[1]

        if success then
            local rc   = results.n - 1
            local rets = {}
            for i = 1, rc do rets[i] = results[i + 1] end

            Log.record(OpCodes.CALL, {
                func = fn, args = unwrapped, argc = unwrapped.n,
                rets = rets, retc = rc,
            })
            return _unpack(results, 2, results.n)
        else
            Log.record(OpCodes.CALL, {
                func = fn, args = unwrapped, argc = unwrapped.n,
                err  = results[2],
            })
            _error(results[2], 2)
        end
    end

    _wrappedFuncs[fn]     = wrapped
    _objectNames[wrapped] = name
    return wrapped
end

function Proxy.wrap(real, name)
    if _type(real) ~= "table" then return real end
    if _realToProxy[real] then return _realToProxy[real] end

    _objectNames[real] = name
    _proxyCount = _proxyCount + 1

    local proxy = {}
    _proxyToReal[proxy] = real
    _realToProxy[real]  = proxy
    _objectNames[proxy] = name

    local meta = {
        __index = function(_, key)
            local value = real[key]
            Log.record(OpCodes.INDEX, { target = real, key = key, value = value })

            if _type(value) == "table" and not _realToProxy[value] then
                return Proxy.wrap(value, name .. "." .. _tostring(key))
            end
            if _type(value) == "function" then
                return Proxy.wrapFunction(value, name .. "." .. _tostring(key))
            end
            return value
        end,

        __newindex = function(_, key, value)
            local uv = Proxy.unwrap(value)
            Log.record(OpCodes.NEWINDEX, { target = real, key = key, value = uv })
            _rawset(real, key, uv)

            if Config.TrackTableMutations then
                _table.insert(Log.tableMutations, {
                    target = name, key = key, value = uv,
                    time = _os_clock() - Log.startTime,
                })
            end
        end,

        __call = function(_, ...)
            local args      = _pack(...)
            local unwrapped = Proxy.unwrapArgs(args, args.n)
            Log.record(OpCodes.CALL, { func = real, args = unwrapped, argc = args.n })
            return real(_unpack(unwrapped, 1, unwrapped.n))
        end,

        __tostring = function(_) return _tostring(real) end,
        __len = function(_)
            Log.record(OpCodes.LEN, { target = real })
            return #real
        end,
        __concat = function(a, b)
            a, b = Proxy.unwrap(a), Proxy.unwrap(b)
            Log.record(OpCodes.CONCAT, { left = a, right = b })
            return _tostring(a) .. _tostring(b)
        end,
        __eq = function(a, b) return Proxy.unwrap(a) == Proxy.unwrap(b) end,
        __lt = function(a, b)
            a, b = Proxy.unwrap(a), Proxy.unwrap(b)
            Log.record(OpCodes.COMPARE, { cmp = "<", left = a, right = b })
            return a < b
        end,
        __le = function(a, b)
            a, b = Proxy.unwrap(a), Proxy.unwrap(b)
            Log.record(OpCodes.COMPARE, { cmp = "<=", left = a, right = b })
            return a <= b
        end,
        __pairs = function(_)
            Log.record(OpCodes.ITERATOR, { target = real, kind = "pairs" })
            return _next, real, nil
        end,
        __ipairs = function(_)
            Log.record(OpCodes.ITERATOR, { target = real, kind = "ipairs" })
            local i = 0
            return function()
                i = i + 1
                local v = real[i]
                if v ~= nil then return i, v end
            end
        end,
    }

    -- Arithmetic metamethods
    local arithOps = { add="+", sub="-", mul="*", div="/", mod="%", pow="^", unm="~", idiv="//" }
    for opN, _ in _pairs(arithOps) do
        meta["__" .. opN] = function(a, b)
            a, b = Proxy.unwrap(a), Proxy.unwrap(b)
            Log.record(OpCodes.ARITH, { arithOp = opN, left = a, right = b })
            local rm = _getmetatable(a)
            if rm and rm["__" .. opN] then return rm["__" .. opN](a, b) end
            if     opN == "add"  then return a + b
            elseif opN == "sub"  then return a - b
            elseif opN == "mul"  then return a * b
            elseif opN == "div"  then return a / b
            elseif opN == "mod"  then return a % b
            elseif opN == "pow"  then return a ^ b
            elseif opN == "unm"  then return -a
            elseif opN == "idiv" then return a // b end
        end
    end

    _setmetatable(proxy, meta)
    return proxy
end

-- ============================================================================
-- STAGE 6: STRING DEOBFUSCATION ENGINE
-- ============================================================================

local StringDeobf = {}

-- Decodes common obfuscation patterns found in obfuscated Lua

--- Detects and decodes string.char based construction
function StringDeobf.decodeCharSequence(args)
    if not args or #args == 0 then return nil end
    local chars = {}
    local allNumbers = true
    for _, v in _ipairs(args) do
        if _type(v) ~= "number" then allNumbers = false; break end
        if v < 0 or v > 255 then allNumbers = false; break end
        _table.insert(chars, _string.char(v))
    end
    if allNumbers and #chars > 0 then
        local result = _table.concat(chars)
        Log.record(OpCodes.VM_STRING_DECRYPT, {
            method    = "string.char",
            encrypted = args,
            decrypted = result,
        })
        _table.insert(Log.stringsDecrypted, {
            method = "string.char", result = result, time = _os_clock() - Log.startTime
        })
        return result
    end
    return nil
end

--- Detects XOR-based string decryption
function StringDeobf.decodeXOR(encrypted, key)
    if _type(encrypted) ~= "string" or _type(key) ~= "number" then return nil end
    local result = {}
    for i = 1, #encrypted do
        local byte = _string.byte(encrypted, i)
        _table.insert(result, _string.char(_bit and _bit.bxor(byte, key) or ((byte + key) % 256)))
    end
    local decoded = _table.concat(result)
    if StringDeobf.isPrintable(decoded) then
        Log.record(OpCodes.VM_STRING_DECRYPT, {
            method    = "xor",
            key       = key,
            encrypted = encrypted,
            decrypted = decoded,
        })
        _table.insert(Log.stringsDecrypted, {
            method = "xor", key = key, result = decoded, time = _os_clock() - Log.startTime
        })
        return decoded
    end
    return nil
end

--- Decodes XOR with string key
function StringDeobf.decodeXORStringKey(encrypted, keyStr)
    if _type(encrypted) ~= "string" or _type(keyStr) ~= "string" then return nil end
    if #keyStr == 0 then return nil end
    local result = {}
    for i = 1, #encrypted do
        local eByte = _string.byte(encrypted, i)
        local kByte = _string.byte(keyStr, ((i - 1) % #keyStr) + 1)
        local xorFn = _bit and _bit.bxor
        if xorFn then
            _table.insert(result, _string.char(xorFn(eByte, kByte)))
        else
            _table.insert(result, _string.char(eByte))
        end
    end
    local decoded = _table.concat(result)
    if StringDeobf.isPrintable(decoded) then
        Log.record(OpCodes.VM_STRING_DECRYPT, {
            method    = "xor_key",
            key       = keyStr,
            encrypted = encrypted,
            decrypted = decoded,
        })
        _table.insert(Log.stringsDecrypted, {
            method = "xor_key", result = decoded, time = _os_clock() - Log.startTime
        })
        return decoded
    end
    return nil
end

--- Base64 decode
function StringDeobf.decodeBase64(input)
    if _type(input) ~= "string" then return nil end
    if not _string.match(input, "^[A-Za-z0-9+/=]+$") then return nil end
    if #input < 4 or #input % 4 ~= 0 then return nil end

    local b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    local result = {}

    input = _string.gsub(input, "[^" .. b64 .. "=]", "")
    input = _string.gsub(input, "=", "")

    for i = 1, #input, 4 do
        local a = _string.find(b64, _string.sub(input, i, i), 1, true) or 0
        local b = _string.find(b64, _string.sub(input, i+1, i+1), 1, true) or 0
        local c = _string.find(b64, _string.sub(input, i+2, i+2), 1, true) or 0
        local d = _string.find(b64, _string.sub(input, i+3, i+3), 1, true) or 0
        a, b, c, d = a - 1, b - 1, c - 1, d - 1

        _table.insert(result, _string.char(
            (a * 4) + _math.floor(b / 16),
            ((b % 16) * 16) + _math.floor(c / 4),
            ((c % 4) * 64) + d
        ))
    end

    local decoded = _table.concat(result)
    if StringDeobf.isPrintable(decoded) then
        Log.record(OpCodes.VM_STRING_DECRYPT, {
            method    = "base64",
            encrypted = _string.sub(input, 1, 100),
            decrypted = decoded,
        })
        _table.insert(Log.stringsDecrypted, {
            method = "base64", result = decoded, time = _os_clock() - Log.startTime
        })
        return decoded
    end
    return nil
end

--- Caesar/shift cipher decode
function StringDeobf.decodeCaesar(input, shift)
    if _type(input) ~= "string" or _type(shift) ~= "number" then return nil end
    local result = {}
    for i = 1, #input do
        _table.insert(result, _string.char((_string.byte(input, i) - shift) % 256))
    end
    local decoded = _table.concat(result)
    if StringDeobf.isPrintable(decoded) then
        _table.insert(Log.stringsDecrypted, {
            method = "caesar", shift = shift, result = decoded, time = _os_clock() - Log.startTime
        })
        return decoded
    end
    return nil
end

--- Reverse string decode
function StringDeobf.decodeReverse(input)
    if _type(input) ~= "string" then return nil end
    return _string.reverse(input)
end

--- Check if a string is mostly printable ASCII
function StringDeobf.isPrintable(s)
    if _type(s) ~= "string" or #s == 0 then return false end
    local printable = 0
    local total     = _math.min(#s, 200)
    for i = 1, total do
        local b = _string.byte(s, i)
        if (b >= 32 and b <= 126) or b == 10 or b == 13 or b == 9 then
            printable = printable + 1
        end
    end
    return (printable / total) > 0.7
end

--- Auto-detect and attempt all decryption methods on a string
function StringDeobf.autoDecrypt(s)
    if _type(s) ~= "string" or #s < 3 then return nil end

    -- Try base64
    local b64 = StringDeobf.decodeBase64(s)
    if b64 then return b64, "base64" end

    -- Try reverse
    local rev = StringDeobf.decodeReverse(s)
    if rev and StringDeobf.isPrintable(rev) and not StringDeobf.isPrintable(s) then
        return rev, "reverse"
    end

    -- Try common XOR keys
    for key = 1, 255 do
        local xored = StringDeobf.decodeXOR(s, key)
        if xored then return xored, "xor:" .. key end
    end

    -- Try common Caesar shifts
    for shift = 1, 25 do
        local shifted = StringDeobf.decodeCaesar(s, shift)
        if shifted then return shifted, "caesar:" .. shift end
    end

    return nil
end

-- ============================================================================
-- STAGE 7: VM DEOBFUSCATION ENGINE
-- ============================================================================

local VMAnalyzer = {}

local _vmPatterns = {
    {
        name = "Luraph",
        confidence = 0,
        signatures = {
            { pattern = "IllIlIIlI", weight = 20 },
            { pattern = "lIlIlIlIl", weight = 20 },
            { pattern = "IlIIIlIIl", weight = 15 },
            { pattern = "bit32%.extract", weight = 10 },
            { pattern = "bit32%.band", weight = 5 },
            { pattern = "while true do", weight = 3 },
        },
    },
    {
        name = "Prometheus",
        confidence = 0,
        signatures = {
            { pattern = "v%d+%(%)", weight = 10 },
            { pattern = "local v%d+ = ", weight = 8 },
            { pattern = "string%.byte", weight = 5 },
            { pattern = "table%.concat", weight = 5 },
            { pattern = "select%(%d+,", weight = 5 },
            { pattern = "string%.sub", weight = 5 },
            { pattern = "string%.char", weight = 5 },
        },
    },
    {
        name = "IronBrew2",
        confidence = 0,
        signatures = {
            { pattern = "Stk%[", weight = 20 },
            { pattern = "Inst%[", weight = 20 },
            { pattern = "InstrPoint", weight = 25 },
            { pattern = "VirtFunc", weight = 20 },
            { pattern = "Upvalues", weight = 10 },
        },
    },
    {
        name = "Moonsec",
        confidence = 0,
        signatures = {
            { pattern = "moon", weight = 5 },
            { pattern = "bytecode", weight = 5 },
            { pattern = "virtual_machine", weight = 15 },
            { pattern = "run_vm", weight = 15 },
            { pattern = "opcode", weight = 10 },
        },
    },
    {
        name = "PSU",
        confidence = 0,
        signatures = {
            { pattern = "PSU", weight = 30 },
            { pattern = "psu_vm", weight = 25 },
            { pattern = "psu_interpret", weight = 25 },
        },
    },
    {
        name = "Aztupbrew",
        confidence = 0,
        signatures = {
            { pattern = "aztup", weight = 30 },
            { pattern = "AztupBrew", weight = 30 },
        },
    },
    {
        name = "Synapse Xen",
        confidence = 0,
        signatures = {
            { pattern = "xen", weight = 5 },
            { pattern = "SynapseXen", weight = 30 },
            { pattern = "_XEN_", weight = 25 },
        },
    },
    {
        name = "WeAreDevs",
        confidence = 0,
        signatures = {
            { pattern = "WeAreDevs", weight = 30 },
            { pattern = "wrd_", weight = 20 },
        },
    },
    {
        name = "Generic VM",
        confidence = 0,
        signatures = {
            { pattern = "while%s+true%s+do", weight = 3 },
            { pattern = "local%s+op%s*=", weight = 10 },
            { pattern = "local%s+stack%s*=", weight = 10 },
            { pattern = "local%s+pc%s*=", weight = 10 },
            { pattern = "local%s+instructions%s*=", weight = 10 },
            { pattern = "string%.byte", weight = 3 },
            { pattern = "bit32%.", weight = 5 },
            { pattern = "table%.move", weight = 5 },
        },
    },
}

--- Identifies which obfuscator was likely used
function VMAnalyzer.identify(code)
    if _type(code) ~= "string" then return nil end

    local results = {}
    for _, pattern in _ipairs(_vmPatterns) do
        local score = 0
        for _, sig in _ipairs(pattern.signatures) do
            if _string.find(code, sig.pattern) then
                score = score + sig.weight
            end
        end
        if score > 0 then
            _table.insert(results, { name = pattern.name, confidence = score })
        end
    end

    _table.sort(results, function(a, b) return a.confidence > b.confidence end)

    if #results > 0 then
        Log.vmIdentification = results
        for _, r in _ipairs(results) do
            Log.record(OpCodes.VM_IDENTIFIED, {
                obfuscator = r.name,
                confidence = r.confidence,
            })
        end
    end

    return results
end

--- Tracks VM loop patterns — detects the main dispatch loop
local _vmLoopDetector = {
    loopCounts    = {},
    funcCallSeqs  = {},
    suspectedVMs  = {},
}

function VMAnalyzer.trackCall(fn, args, rets)
    if not Config.VM.Enabled then return end

    local fnName = _objectNames[fn] or _tostring(fn)

    -- Track call frequency
    _vmLoopDetector.loopCounts[fnName] = (_vmLoopDetector.loopCounts[fnName] or 0) + 1

    local count = _vmLoopDetector.loopCounts[fnName]

    -- If a function is called excessively, it's likely a VM dispatch loop
    if count == 100 then
        Log.record(OpCodes.VM_LOOP, {
            func      = fn,
            funcName  = fnName,
            callCount = count,
            text      = "Suspected VM dispatch loop detected",
        })
    end

    -- Track sequences for opcode pattern detection
    if count > 10 and count < Config.VM.MaxOpcodeCapture then
        if args and args.n and args.n > 0 then
            local opEntry = {
                func = fnName,
                args = {},
                time = _os_clock() - Log.startTime,
            }
            for i = 1, _math.min(args.n, 5) do
                opEntry.args[i] = args[i]
            end
            _table.insert(Log.vmOpcodes, opEntry)

            -- Check if args look like opcodes (numbers)
            if _type(args[1]) == "number" then
                Log.record(OpCodes.VM_OPCODE, {
                    opcode  = args[1],
                    opname  = "OP_" .. _tostring(args[1]),
                    A       = args[2],
                    B       = args[3],
                    C       = args[4],
                })
            end
        end
    end
end

--- Attempts to trace VM stack operations from call patterns
function VMAnalyzer.traceVMStack(fn, args)
    if not Config.VM.CaptureVMStack then return end

    -- Detect common VM stack patterns:
    -- stack[top] = value, stack[top + 1] = value, etc.
    if args and args.n and args.n >= 2 then
        if _type(args[1]) == "table" and _type(args[2]) == "number" then
            Log.record(OpCodes.VM_STACK_OP, {
                stack = Serializer.nameOf(args[1], "vm_stack"),
                index = args[2],
                value = args[3],
            })
        end
    end
end

--- Analyzes closure chains to detect VM-wrapped functions
function VMAnalyzer.analyzeClosureChain(fn, depth)
    if not Config.VM.FollowClosureChains then return end
    depth = depth or 0
    if depth > 20 then return end
    if not fn or _type(fn) ~= "function" then return end

    local name = _objectNames[fn] or "closure_" .. Log.nextId()

    -- Get upvalues
    if _getupvalues then
        local ok, ups = _pcall(_getupvalues, fn)
        if ok and ups then
            for idx, val in _pairs(ups) do
                if _type(val) == "function" then
                    Log.record(OpCodes.VM_CLOSURE_CREATE, {
                        parent  = name,
                        child   = Serializer.nameOf(val, "vm_closure"),
                        upIndex = idx,
                        depth   = depth,
                    })
                    VMAnalyzer.analyzeClosureChain(val, depth + 1)
                elseif _type(val) == "table" then
                    -- Tables in upvalues might contain bytecode/instructions
                    local tableSize = 0
                    for _ in _pairs(val) do tableSize = tableSize + 1 end
                    if tableSize > 20 then
                        Log.record(OpCodes.VM_TABLE_BUILD, {
                            parent = name,
                            upIndex = idx,
                            tableSize = tableSize,
                            text = "Large table in upvalue — possible instruction set",
                        })
                    end
                elseif _type(val) == "string" and #val > 50 then
                    -- Large strings might be encoded bytecode
                    local decoded, method = StringDeobf.autoDecrypt(val)
                    if decoded then
                        Log.record(OpCodes.VM_STRING_DECRYPT, {
                            parent    = name,
                            method    = method,
                            encrypted = _string.sub(val, 1, 100),
                            decrypted = _string.sub(decoded, 1, 200),
                        })
                    end
                end
            end
        end
    end

    -- Get constants
    if _getconstants then
        local ok, consts = _pcall(_getconstants, fn)
        if ok and consts then
            for idx, val in _pairs(consts) do
                if _type(val) == "string" and #val > 10 then
                    if Config.DeobfuscateStrings then
                        local decoded, method = StringDeobf.autoDecrypt(val)
                        if decoded then
                            Log.record(OpCodes.VM_STRING_DECRYPT, {
                                parent    = name,
                                constIdx  = idx,
                                method    = method,
                                encrypted = _string.sub(val, 1, 100),
                                decrypted = _string.sub(decoded, 1, 200),
                            })
                        end
                    end
                end
            end
        end
    end
end

--- Generates a VM analysis report
function VMAnalyzer.report()
    local lines = {}
    _table.insert(lines, "═══ VM ANALYSIS REPORT ═══")
    _table.insert(lines, "")

    -- Obfuscator identification
    if #Log.vmIdentification > 0 then
        _table.insert(lines, "── Obfuscator Identification ──")
        for _, r in _ipairs(Log.vmIdentification) do
            _table.insert(lines, _string.format("  %s (confidence: %d%%)", r.name, r.confidence))
        end
        _table.insert(lines, "")
    end

    -- VM dispatch loops
    _table.insert(lines, "── Suspected VM Dispatch Loops ──")
    local sortedLoops = {}
    for fn, count in _pairs(_vmLoopDetector.loopCounts) do
        if count > 50 then
            _table.insert(sortedLoops, { func = fn, count = count })
        end
    end
    _table.sort(sortedLoops, function(a, b) return a.count > b.count end)
    for i = 1, _math.min(#sortedLoops, 20) do
        _table.insert(lines, _string.format("  %-50s %d calls", sortedLoops[i].func, sortedLoops[i].count))
    end
    _table.insert(lines, "")

    -- Captured opcodes
    _table.insert(lines, _string.format("── VM Opcodes Captured: %d ──", #Log.vmOpcodes))
    for i = 1, _math.min(#Log.vmOpcodes, 100) do
        local op = Log.vmOpcodes[i]
        _table.insert(lines, _string.format("  [%.3fs] %s args: %s",
            op.time or 0, op.func or "?", Serializer.serialize(op.args)))
    end
    if #Log.vmOpcodes > 100 then
        _table.insert(lines, _string.format("  ... +%d more", #Log.vmOpcodes - 100))
    end
    _table.insert(lines, "")

    -- Decrypted strings
    if #Log.stringsDecrypted > 0 then
        _table.insert(lines, _string.format("── Decrypted Strings: %d ──", #Log.stringsDecrypted))
        for _, s in _ipairs(Log.stringsDecrypted) do
            _table.insert(lines, _string.format("  [%s] %s",
                s.method or "?", Serializer.serializeString(s.result or "")))
        end
        _table.insert(lines, "")
    end

    return _table.concat(lines, "\n")
end

-- ============================================================================
-- STAGE 8: URL DEOBFUSCATION ENGINE
-- ============================================================================

local UrlEngine = {}

function UrlEngine.extractUrls(str)
    if _type(str) ~= "string" then return {} end
    local urls = {}
    local seen = {}

    local patterns = {
        "(https?://[%w%-%._~:/?#%[%]@!$&'%(%)%*%+,;=%%]+)",
        "(raw%.githubusercontent%.com/[%w%-%._~/]+)",
        "(pastebin%.com/raw/[%w]+)",
        "(hastebin%.com/raw/[%w]+)",
        "(pastie%.io/raw/[%w]+)",
        "(gist%.githubusercontent%.com/[%w%-%._~/]+)",
        "(cdn%.discordapp%.com/attachments/[%d]+/[%d]+/[%w%-%._]+)",
        "(rentry%.co/[%w]+/raw)",
        "(textbin%.net/raw/[%w]+)",
        "(rbxassetid://[%d]+)",
        "(ghostbin%.com/paste/[%w]+/raw)",
    }

    for _, pat in _ipairs(patterns) do
        for url in _string.gmatch(str, pat) do
            if not _string.match(url, "^https?://") and not _string.match(url, "^rbxassetid://") then
                url = "https://" .. url
            end
            if not seen[url] then
                seen[url] = true
                _table.insert(urls, url)
            end
        end
    end
    return urls
end

function UrlEngine.fetch(url)
    if not url or _type(url) ~= "string" or #url > 4096 then return nil, "invalid url" end

    -- Method 1: request()
    if _request then
        local ok, result = _pcall(_request, {
            Url     = url,
            Method  = "GET",
            Headers = { ["User-Agent"] = "Mozilla/5.0", ["Accept"] = "*/*" },
        })
        if ok and result then
            if _type(result) == "table" and result.Body then
                return result.Body, result.StatusCode
            elseif _type(result) == "string" then
                return result, 200
            end
        end
    end

    -- Method 2: game:HttpGet
    if _httpget then
        local ok, result = _pcall(_httpget, url)
        if ok and result then return result, 200 end
    end

    -- Method 3: HttpService
    if _HttpService then
        local ok, result = _pcall(function() return _HttpService:GetAsync(url) end)
        if ok and result then return result, 200 end
    end

    return nil, "no http method available"
end

function UrlEngine.deobfuscateUrl(url, depth)
    depth = depth or 0
    if depth > Config.MaxUrlRecursionDepth then return nil, "max depth" end
    if Log.urlsDiscovered[url] then return Log.urlsDiscovered[url], "cached" end

    Log.record(OpCodes.DEOBF_URL, { url = url, depth = depth, size = 0 })

    local content, status = UrlEngine.fetch(url)
    if not content then
        Log.record(OpCodes.COMMENT, { text = "FETCH FAILED: " .. url .. " (" .. _tostring(status) .. ")" })
        return nil, status
    end

    Log.urlsDiscovered[url] = content
    Log.record(OpCodes.HTTP_FETCH, {
        url        = url,
        status     = status,
        size       = #content,
        httpMethod = "GET",
    })

    -- Identify obfuscator in fetched content
    if Config.VM.Enabled and Config.VM.IdentifyObfuscator then
        VMAnalyzer.identify(content)
    end

    -- Recursive URL discovery
    if Config.RecursiveTrace then
        local innerUrls = UrlEngine.extractUrls(content)
        for _, innerUrl in _ipairs(innerUrls) do
            if not Log.urlsDiscovered[innerUrl] and innerUrl ~= url then
                Log.record(OpCodes.COMMENT, { text = "Nested URL: " .. innerUrl })
                _task_spawn(function()
                    UrlEngine.deobfuscateUrl(innerUrl, depth + 1)
                end)
            end
        end
    end

    -- Record as script if it's Lua
    if Config.RecursiveTrace and UrlEngine.looksLikeLua(content) then
        _table.insert(Log.scriptsLoaded, {
            source = url,
            code   = content,
            size   = #content,
            time   = _os_clock() - Log.startTime,
        })

        -- Try to compile and analyze
        if Config.CaptureClosureUpvalues then
            local ok, fn = _pcall(_loadstring, content)
            if ok and fn then
                _task_spawn(function()
                    ClosureAnalyzer.analyze(fn, "url:" .. url)
                    if Config.VM.FollowClosureChains then
                        VMAnalyzer.analyzeClosureChain(fn)
                    end
                end)
            end
        end
    end

    return content, status
end

function UrlEngine.looksLikeLua(content)
    if _type(content) ~= "string" or #content < 10 then return false end

    local luaSignals = {
        "function%s",  "local%s",     "return%s",  "end[%s;]",
        "if%s",        "then%s",      "for%s",     "while%s",
        "require%s*%(","loadstring%s*%(","game%s*:", "getfenv",
        "setfenv",     "pcall%s*%(",   "string%.",  "table%.",
        "math%.",      "coroutine%.",  "bit32%.",   "select%(",
    }

    local obfSignals = {
        "string%.char%s*%(", "string%.byte%s*%(", "string%.sub%s*%(",
        "string%.rep%s*%(",  "table%.concat",     "bit%.bxor",
        "bit32%.extract",    "bit32%.band",       "load%s*%(",
        "\\%d+\\%d+",
    }

    local score = 0
    for _, p in _ipairs(luaSignals) do
        if _string.find(content, p) then score = score + 1 end
    end
    for _, p in _ipairs(obfSignals) do
        if _string.find(content, p) then score = score + 2 end
    end

    return score >= 2
end

-- ============================================================================
-- STAGE 9: CLOSURE ANALYZER
-- ============================================================================

local ClosureAnalyzer = {}

function ClosureAnalyzer.analyze(fn, name)
    if _type(fn) ~= "function" then return nil end
    name = name or Serializer.nameOf(fn, "func")

    if Log.closureMap[fn] then return Log.closureMap[fn] end

    local info = { name = name }

    -- Debug info
    if _getinfo then
        local ok, di = _pcall(_getinfo, fn)
        if ok and di then
            info.source      = di.source or di.short_src
            info.lineDefined = di.linedefined
            info.lastLine    = di.lastlinedefined
            info.numParams   = di.numparams or di.nparams
            info.isVararg    = di.is_vararg or di.isvararg
            info.numUpvalues = di.nups
            info.what        = di.what
        end
    end

    -- Upvalues
    if _getupvalues then
        local ok, ups = _pcall(_getupvalues, fn)
        if ok and ups then
            info.upvalues = {}
            for idx, val in _pairs(ups) do
                info.upvalues[idx] = val
                Log.record(OpCodes.UPVALUE, { funcName = name, index = idx, value = val })
            end
        end
    elseif _getupvalue then
        info.upvalues = {}
        for i = 1, 250 do
            local ok, uName, uVal = _pcall(_getupvalue, fn, i)
            if not ok or uName == nil then break end
            info.upvalues[i] = { name = uName, value = uVal }
            Log.record(OpCodes.UPVALUE, { funcName = name, index = i, upvalName = uName, value = uVal })
        end
    end

    -- Constants
    if _getconstants then
        local ok, consts = _pcall(_getconstants, fn)
        if ok and consts then
            info.constants = consts
            for idx, val in _pairs(consts) do
                Log.record(OpCodes.CONSTANT, { funcName = name, index = idx, value = val })
            end
        end
    end

    -- Protos
    if _getprotos then
        local ok, protos = _pcall(_getprotos, fn)
        if ok and protos then
            info.protos = {}
            for idx, proto in _pairs(protos) do
                info.protos[idx] = ClosureAnalyzer.analyze(proto, name .. ".proto_" .. idx)
            end
        end
    end

    -- Decompile
    if _decompile then
        local ok, dec = _pcall(_decompile, fn)
        if ok and dec then info.decompiled = dec end
    end

    -- Closure type
    if _islclosure then
        local ok, r = _pcall(_islclosure, fn)
        if ok then info.isLClosure = r end
    end
    if _iscclosure then
        local ok, r = _pcall(_iscclosure, fn)
        if ok then info.isCClosure = r end
    end

    Log.closureMap[fn] = info
    return info
end

function ClosureAnalyzer.scanGC()
    if not _getgc then return {} end
    Log.record(OpCodes.GC_SCAN, { text = "Scanning GC" })

    local results = {}
    local ok, gc = _pcall(_getgc, true)
    if not ok or not gc then return results end

    local count = 0
    for _, obj in _ipairs(gc) do
        if count >= Config.MaxGCScanObjects then break end
        if _type(obj) == "function" then
            local info = ClosureAnalyzer.analyze(obj, "gc_func_" .. count)
            if info then
                _table.insert(results, info)
                count = count + 1
            end
        end
    end

    Log.record(OpCodes.COMMENT, { text = _string.format("GC scan: %d closures found", count) })
    return results
end

function ClosureAnalyzer.scanRegistry()
    if not _getreg then return {} end
    Log.record(OpCodes.COMMENT, { text = "Scanning registry" })

    local results = {}
    local ok, reg = _pcall(_getreg)
    if not ok or not reg then return results end

    local count = 0
    for _, entry in _ipairs(reg) do
        if count >= 500 then break end
        if _type(entry) == "function" then
            local info = ClosureAnalyzer.analyze(entry, "reg_func_" .. count)
            if info then _table.insert(results, info); count = count + 1 end
        elseif _type(entry) == "table" then
            for k, v in _pairs(entry) do
                if _type(v) == "function" and count < 500 then
                    local info = ClosureAnalyzer.analyze(v, "reg_tbl_func_" .. count)
                    if info then _table.insert(results, info); count = count + 1 end
                end
            end
        end
    end

    return results
end

-- ============================================================================
-- STAGE 10: NAMECALL HOOK
-- ============================================================================

local NamecallHook = {}

function NamecallHook.install()
    if not _getrawmetatable or not Config.IsRoblox then return end
    if not _newcclosure then return end

    local gameMeta = _getrawmetatable(game)
    if not gameMeta then return end

    local origNamecall = gameMeta.__namecall
    local origIndex    = gameMeta.__index
    local origNewindex = gameMeta.__newindex

    if _setreadonly then _pcall(_setreadonly, gameMeta, false) end

    -- __namecall hook
    if origNamecall then
        gameMeta.__namecall = _newcclosure(function(self, ...)
            local method = _getnamecallmethod and _getnamecallmethod() or "?"
            local args   = _pack(...)
            local uArgs  = Proxy.unwrapArgs(args, args.n)

            -- Remote interception
            if method == "FireServer" then
                local remotePath = _pcall(function() return self:GetFullName() end) and self:GetFullName() or "?"
                local remoteName = _pcall(function() return self.Name end) and self.Name or "?"

                Log.record(OpCodes.REMOTE_FIRE, {
                    target = self, path = remotePath, name = remoteName,
                    method = method, args = uArgs, argc = uArgs.n,
                })
                _table.insert(Log.remotesCaptured, {
                    remote = self, path = remotePath, name = remoteName,
                    method = "FireServer", args = uArgs,
                    time = _os_clock() - Log.startTime,
                })
            elseif method == "InvokeServer" then
                local remotePath = _pcall(function() return self:GetFullName() end) and self:GetFullName() or "?"
                local remoteName = _pcall(function() return self.Name end) and self.Name or "?"

                Log.record(OpCodes.REMOTE_INVOKE, {
                    target = self, path = remotePath, name = remoteName,
                    method = method, args = uArgs, argc = uArgs.n,
                })
                _table.insert(Log.remotesCaptured, {
                    remote = self, path = remotePath, name = remoteName,
                    method = "InvokeServer", args = uArgs,
                    time = _os_clock() - Log.startTime,
                })
            end

            -- HTTP interception
            if method == "HttpGet" or method == "HttpGetAsync" or
               method == "HttpPost" or method == "HttpPostAsync" or
               method == "GetAsync" or method == "PostAsync" or
               method == "RequestAsync" then

                Log.record(OpCodes.HTTP_FETCH, {
                    target = self, method = method,
                    url = uArgs[1], httpMethod = method,
                    args = uArgs, argc = uArgs.n,
                })

                if Config.DeobfuscateUrls and uArgs[1] and _type(uArgs[1]) == "string" then
                    _task_spawn(function()
                        UrlEngine.deobfuscateUrl(uArgs[1])
                    end)
                end
            end

            -- Generic namecall log
            Log.record(OpCodes.NAMECALL, {
                target = self, method = method,
                args = uArgs, argc = uArgs.n,
            })

            -- Execute original
            local results = _pack(origNamecall(self, ...))

            -- Capture return values for remotes
            if (method == "InvokeServer") and results.n > 0 then
                local rets = {}
                for i = 1, results.n do rets[i] = results[i] end
                Log.record(OpCodes.NAMECALL, {
                    target = self, method = method .. "_RETURN",
                    rets = rets, retc = results.n,
                })
            end

            return _unpack(results, 1, results.n)
        end)
    end

    -- __index hook
    if origIndex and _newcclosure then
        gameMeta.__index = _newcclosure(function(self, key)
            local value = origIndex(self, key)
            -- Only log non-spammy accesses
            if _type(key) == "string" then
                Log.record(OpCodes.INDEX, { target = self, key = key, value = value })
            end
            return value
        end)
    end

    if _setreadonly then _pcall(_setreadonly, gameMeta, true) end
    Log.record(OpCodes.COMMENT, { text = "Namecall hooks installed" })
end

-- ============================================================================
-- STAGE 11: HOOKER — Full Environment Builder
-- ============================================================================

local Hooker = {}

function Hooker.hookLibrary(target, libName, source)
    for name, fn in _pairs(source) do
        if _type(fn) == "function" then
            target[name] = Proxy.wrapFunction(fn, libName .. "." .. name)
        else
            target[name] = fn
        end
    end
end

function Hooker.buildEnvironment(baseEnv)
    local env = {}
    for k, v in _pairs(baseEnv) do env[k] = v end

    -- Helper to hook a global
    local function hook(name, wrapper)
        env[name] = wrapper
        _objectNames[wrapper] = name
    end

    -- ═══════════════════════════════
    -- CORE GLOBALS
    -- ═══════════════════════════════

    hook("type", function(v)
        v = Proxy.unwrap(v)
        local r = _type(v)
        Log.record(OpCodes.CALL, { func = _type, args = {v}, argc = 1, rets = {r}, retc = 1 })
        return r
    end)

    if _typeof and _typeof ~= _type then
        hook("typeof", function(v)
            v = Proxy.unwrap(v)
            local r = _typeof(v)
            Log.record(OpCodes.CALL, { func = _typeof, args = {v}, argc = 1, rets = {r}, retc = 1 })
            return r
        end)
    end

    hook("tostring", function(v)
        v = Proxy.unwrap(v)
        local r = _tostring(v)
        Log.record(OpCodes.TOSTRING, { input = v, output = r })
        return r
    end)

    hook("tonumber", function(v, base)
        v = Proxy.unwrap(v)
        local r = base and _tonumber(v, base) or _tonumber(v)
        Log.record(OpCodes.TONUMBER, { input = v, base = base, output = r })
        return r
    end)

    hook("pcall", function(fn, ...)
        fn = Proxy.unwrap(fn)
        local args = _pack(...)
        local ua   = Proxy.unwrapArgs(args, args.n)

        -- Track for VM analysis
        VMAnalyzer.trackCall(fn, ua)

        local results = _pack(_pcall(fn, _unpack(ua, 1, ua.n)))
        if not results[1] then
            _table.insert(Log.errorsLogged, { message = results[2], time = _os_clock() - Log.startTime })
            Log.record(OpCodes.ERROR_CAUGHT, { message = results[2], func = fn })
        end

        Log.record(OpCodes.CALL, {
            func = fn, args = ua, argc = ua.n,
            rets = { results[1] }, retc = 1,
        })

        return _unpack(results, 1, results.n)
    end)

    hook("xpcall", function(fn, handler, ...)
        fn, handler = Proxy.unwrap(fn), Proxy.unwrap(handler)
        local args = _pack(...)
        local ua   = Proxy.unwrapArgs(args, args.n)
        VMAnalyzer.trackCall(fn, ua)
        Log.record(OpCodes.CALL, { func = fn, args = ua, argc = ua.n })
        return _xpcall(fn, handler, _unpack(ua, 1, ua.n))
    end)

    hook("select", function(idx, ...)
        Log.record(OpCodes.CALL, { func = _select, args = {idx}, argc = 1 })
        return _select(idx, ...)
    end)

    hook("unpack", function(t, i, j)
        t = Proxy.unwrap(t)
        Log.record(OpCodes.CALL, { func = _unpack, args = {t, i, j}, argc = 3 })
        return _unpack(t, i, j)
    end)

    hook("assert", function(v, ...)
        v = Proxy.unwrap(v)
        return _assert(v, ...)
    end)

    hook("error", function(msg, lvl)
        Log.record(OpCodes.ERROR_CAUGHT, { message = msg })
        _table.insert(Log.errorsLogged, { message = msg, time = _os_clock() - Log.startTime })
        _error(msg, (lvl or 1) + 1)
    end)

    -- Raw operations
    hook("rawget", function(t, k)
        t = Proxy.unwrap(t)
        local r = _rawget(t, k)
        Log.record(OpCodes.RAWOP, { kind = "rawget", target = t, key = k, value = r })
        return r
    end)
    hook("rawset", function(t, k, v)
        t, v = Proxy.unwrap(t), Proxy.unwrap(v)
        Log.record(OpCodes.RAWOP, { kind = "rawset", target = t, key = k, value = v })
        return _rawset(t, k, v)
    end)
    hook("rawequal", function(a, b)
        a, b = Proxy.unwrap(a), Proxy.unwrap(b)
        Log.record(OpCodes.RAWOP, { kind = "rawequal", left = a, right = b })
        return _rawequal(a, b)
    end)
    if _rawlen then
        hook("rawlen", function(t)
            t = Proxy.unwrap(t)
            Log.record(OpCodes.RAWOP, { kind = "rawlen", target = t })
            return _rawlen(t)
        end)
    end

    -- Iterators
    hook("pairs", function(t)
        t = Proxy.unwrap(t)
        Log.record(OpCodes.ITERATOR, { target = t, kind = "pairs" })
        return _pairs(t)
    end)
    hook("ipairs", function(t)
        t = Proxy.unwrap(t)
        Log.record(OpCodes.ITERATOR, { target = t, kind = "ipairs" })
        return _ipairs(t)
    end)
    hook("next", function(t, k)
        t = Proxy.unwrap(t)
        return _next(t, k)
    end)

    -- ═══════════════════════════════
    -- METATABLE HOOKS
    -- ═══════════════════════════════

    if Config.HookMetatables then
        hook("setmetatable", function(t, mt)
            t, mt = Proxy.unwrap(t), Proxy.unwrap(mt)
            Log.record(OpCodes.METATABLE, { kind = "set", target = t, metatable = mt })
            return _setmetatable(t, mt)
        end)
        hook("getmetatable", function(t)
            t = Proxy.unwrap(t)
            local mt = _getmetatable(t)
            Log.record(OpCodes.METATABLE, { kind = "get", target = t, metatable = mt })
            return mt
        end)
    end

    -- ═══════════════════════════════
    -- GETFENV/SETFENV (anti-detection)
    -- ═══════════════════════════════

    if Config.HookGetfenv and _getfenv then
        hook("getfenv", function(level)
            Log.record(OpCodes.GETFENV, { level = level })
            if Config.HideFromGetfenv then return env end
            return _getfenv(level)
        end)
    end

    if Config.HookGetfenv and _setfenv then
        hook("setfenv", function(level, newEnv)
            Log.record(OpCodes.SETFENV, { level = level })
            if Config.PreventUnhooking then
                Log.record(OpCodes.BLOCKED, { action = "setfenv", text = "Blocked setfenv (anti-unhook)" })
                _table.insert(Log.blockedOperations, {
                    action = "setfenv", time = _os_clock() - Log.startTime
                })
                return level
            end
            return _setfenv(level, newEnv)
        end)
    end

    -- ═══════════════════════════════
    -- LOADSTRING HOOK (critical)
    -- ═══════════════════════════════

    if Config.HookLoadstring then
        local function hookedLoadstring(code, chunkName)
            code = Proxy.unwrap(code)
            local codeStr = _tostring(code)
            local codeLen = #codeStr

            Log.record(OpCodes.LOADSTRING, {
                code       = _string.sub(codeStr, 1, 1000),
                codeLength = codeLen,
                chunkName  = chunkName,
            })

            -- URL discovery in loaded code
            if Config.DeobfuscateUrls then
                local urls = UrlEngine.extractUrls(codeStr)
                for _, url in _ipairs(urls) do
                    if not Log.urlsDiscovered[url] then
                        Log.record(OpCodes.COMMENT, { text = "URL in loadstring: " .. url })
                        _task_spawn(function() UrlEngine.deobfuscateUrl(url) end)
                    end
                end
            end

            -- VM identification
            if Config.VM.Enabled and Config.VM.IdentifyObfuscator then
                VMAnalyzer.identify(codeStr)
            end

            -- Record script
            _table.insert(Log.scriptsLoaded, {
                source = "loadstring:" .. (chunkName or "chunk_" .. #Log.scriptsLoaded),
                code   = codeStr,
                size   = codeLen,
                time   = _os_clock() - Log.startTime,
            })

            -- Compile
            local fn, err = _loadstring(code, chunkName)
            if fn then
                if _setfenv then _setfenv(fn, env) end

                -- Closure analysis
                if Config.CaptureClosureUpvalues then
                    _task_spawn(function()
                        ClosureAnalyzer.analyze(fn, "loadstring:" .. (chunkName or "chunk"))
                        if Config.VM.FollowClosureChains then
                            VMAnalyzer.analyzeClosureChain(fn)
                        end
                    end)
                end

                return Proxy.wrapFunction(fn, "loadstring_result_" .. #Log.scriptsLoaded), nil
            end
            return nil, err
        end

        hook("loadstring", hookedLoadstring)
        if baseEnv.load and baseEnv.load ~= baseEnv.loadstring then
            hook("load", hookedLoadstring)
        end
    end

    -- ═══════════════════════════════
    -- HTTP REQUEST HOOKS
    -- ═══════════════════════════════

    if Config.HookHttpRequests then
        local function createHttpHook(origFn, fnName)
            if not origFn then return nil end
            return function(opts)
                opts = Proxy.unwrapDeep(opts)
                local url = _type(opts) == "string" and opts
                    or (_type(opts) == "table" and (opts.Url or opts.url))

                Log.record(OpCodes.HTTP_FETCH, {
                    url        = url,
                    httpMethod = (_type(opts) == "table" and (opts.Method or opts.method)) or "GET",
                    args       = opts,
                })

                if Config.DeobfuscateUrls and url then
                    _task_spawn(function() UrlEngine.deobfuscateUrl(url) end)
                end

                local results = _pack(_pcall(origFn, opts))
                if results[1] then
                    local response = results[2]
                    if _type(response) == "table" and response.Body then
                        Log.record(OpCodes.HTTP_FETCH, {
                            url        = url,
                            status     = response.StatusCode,
                            size       = #response.Body,
                            httpMethod = "RESPONSE",
                        })
                        if Config.RecursiveTrace then
                            local innerUrls = UrlEngine.extractUrls(response.Body)
                            for _, iu in _ipairs(innerUrls) do
                                if not Log.urlsDiscovered[iu] then
                                    _task_spawn(function() UrlEngine.deobfuscateUrl(iu) end)
                                end
                            end
                            if UrlEngine.looksLikeLua(response.Body) then
                                _table.insert(Log.scriptsLoaded, {
                                    source = "http:" .. (url or "?"),
                                    code   = response.Body,
                                    size   = #response.Body,
                                    time   = _os_clock() - Log.startTime,
                                })
                            end
                        end
                    end
                    return _unpack(results, 2, results.n)
                else
                    Log.record(OpCodes.ERROR_CAUGHT, { message = results[2] })
                    _error(results[2], 2)
                end
            end
        end

        if _request then
            local hookedReq = createHttpHook(_request, "request")
            env.request      = hookedReq
            env.http_request = hookedReq
        end
        if _syn_request then
            env.syn = env.syn or {}
            if _type(env.syn) == "table" then
                env.syn.request = createHttpHook(_syn_request, "syn.request")
            end
        end
        if _httpget then
            hook("httpget", function(url)
                url = Proxy.unwrap(url)
                Log.record(OpCodes.HTTP_FETCH, { url = url, httpMethod = "HttpGet" })
                if Config.DeobfuscateUrls then
                    _task_spawn(function() UrlEngine.deobfuscateUrl(url) end)
                end
                return _httpget(url)
            end)
        end
    end

    -- ═══════════════════════════════
    -- CLIPBOARD
    -- ═══════════════════════════════

    if Config.HookClipboard then
        if _setclipboard then
            hook("setclipboard", function(text)
                text = Proxy.unwrap(text)
                Log.record(OpCodes.CLIPBOARD, { action = "set", text = text })
                return _setclipboard(text)
            end)
        end
        if _getclipboard then
            hook("getclipboard", function()
                local r = _getclipboard()
                Log.record(OpCodes.CLIPBOARD, { action = "get", text = r })
                return r
            end)
        end
    end

    -- ═══════════════════════════════
    -- PRINT / WARN
    -- ═══════════════════════════════

    hook("print", function(...)
        local args = _pack(...)
        Log.record(OpCodes.CALL, { func = _print, args = args, argc = args.n })
        _print(...)
    end)
    hook("warn", function(...)
        local args = _pack(...)
        Log.record(OpCodes.CALL, { func = _warn, args = args, argc = args.n })
        _warn(...)
    end)

    -- ═══════════════════════════════
    -- SPAWN / DELAY / TASK
    -- ═══════════════════════════════

    if Config.HookSpawn then
        if baseEnv.spawn then
            hook("spawn", function(fn)
                fn = Proxy.unwrap(fn)
                Log.record(OpCodes.CALL, { func = "spawn", args = {fn}, argc = 1 })
                if _setfenv and _type(fn) == "function" then
                    _pcall(_setfenv, fn, env)
                end
                return _task_spawn(fn)
            end)
        end
        if task then
            env.task = env.task or {}
            env.task.spawn = function(fn, ...)
                fn = Proxy.unwrap(fn)
                Log.record(OpCodes.CALL, { func = "task.spawn", args = {fn}, argc = 1 })
                if _setfenv and _type(fn) == "function" then
                    _pcall(_setfenv, fn, env)
                end
                return _task_spawn(fn, ...)
            end
            env.task.defer = function(fn, ...)
                fn = Proxy.unwrap(fn)
                Log.record(OpCodes.CALL, { func = "task.defer", args = {fn}, argc = 1 })
                if _setfenv and _type(fn) == "function" then
                    _pcall(_setfenv, fn, env)
                end
                return _task_defer(fn, ...)
            end
            env.task.delay = function(t, fn, ...)
                fn = Proxy.unwrap(fn)
                Log.record(OpCodes.CALL, { func = "task.delay", args = {t, fn}, argc = 2 })
                if _setfenv and _type(fn) == "function" then
                    _pcall(_setfenv, fn, env)
                end
                return _task_delay(t, fn, ...)
            end
            env.task.wait = _task_wait
        end
    end

    -- ═══════════════════════════════
    -- REQUIRE
    -- ═══════════════════════════════

    if Config.HookRequire and baseEnv.require then
        local realRequire = baseEnv.require
        hook("require", function(target)
            target = Proxy.unwrap(target)
            Log.record(OpCodes.REQUIRE, { target = target })
            local results = _pack(_pcall(realRequire, target))
            if results[1] then
                local module = results[2]
                if Config.CaptureClosureUpvalues and _type(module) == "function" then
                    ClosureAnalyzer.analyze(module, "require:" .. _tostring(target))
                end
                return module
            else
                Log.record(OpCodes.ERROR_CAUGHT, { message = results[2] })
                _error(results[2], 2)
            end
        end)
    end

    -- ═══════════════════════════════
    -- STANDARD LIBRARIES
    -- ═══════════════════════════════

    if Config.HookStringLib then
        env.string = {}
        Hooker.hookLibrary(env.string, "string", _string)

        -- Special hook for string.char — string deobfuscation
        local origStringChar = _string.char
        env.string.char = function(...)
            local args = _pack(...)
            local result = origStringChar(...)

            Log.record(OpCodes.CALL, {
                func = origStringChar, args = args, argc = args.n,
                rets = {result}, retc = 1,
            })

            -- Attempt string decryption detection
            if Config.DeobfuscateStrings and args.n > 3 then
                StringDeobf.decodeCharSequence({_unpack(args, 1, args.n)})
            end

            return result
        end
        _objectNames[env.string.char] = "string.char"

        -- Hook string.byte for tracking
        local origStringByte = _string.byte
        env.string.byte = function(s, i, j)
            s = Proxy.unwrap(s)
            local results = _pack(origStringByte(s, i, j))
            Log.record(OpCodes.CALL, {
                func = origStringByte, args = {s, i, j}, argc = 3,
                rets = results, retc = results.n,
            })
            return _unpack(results, 1, results.n)
        end
        _objectNames[env.string.byte] = "string.byte"
    end

    if Config.HookMathLib then
        env.math = {}
        Hooker.hookLibrary(env.math, "math", _math)
        env.math.pi         = _math.pi
        env.math.huge       = _math.huge
        env.math.maxinteger = _math.maxinteger
        env.math.mininteger = _math.mininteger
    end

    if Config.HookTableLib then
        env.table = {}
        Hooker.hookLibrary(env.table, "table", _table)
    end

    if Config.HookCoroutines then
        env.coroutine = {}
        for k, v in _pairs(_coroutine) do
            if _type(v) == "function" then
                env.coroutine[k] = Proxy.wrapFunction(v, "coroutine." .. k)
            else
                env.coroutine[k] = v
            end
        end
    end

    if Config.HookBitLib and _bit then
        env.bit32 = env.bit32 or {}
        env.bit   = env.bit or {}
        for k, v in _pairs(_bit) do
            if _type(v) == "function" then
                env.bit32[k] = Proxy.wrapFunction(v, "bit32." .. k)
                env.bit[k]   = env.bit32[k]
            else
                env.bit32[k] = v
                env.bit[k]   = v
            end
        end
    end

    if Config.HookDebugLib and _debug then
        env.debug = {}
        for k, v in _pairs(_debug) do
            if _type(v) == "function" then
                if Config.BlockDebugAccess and (k == "getinfo" or k == "getupvalue" or k == "setupvalue") then
                    env.debug[k] = function(...)
                        Log.record(OpCodes.BLOCKED, {
                            action = "debug." .. k,
                            text   = "Blocked debug access (anti-tamper)",
                        })
                        _table.insert(Log.blockedOperations, {
                            action = "debug." .. k,
                            time   = _os_clock() - Log.startTime,
                        })
                        return v(...)  -- still execute but log it
                    end
                    _objectNames[env.debug[k]] = "debug." .. k
                else
                    env.debug[k] = Proxy.wrapFunction(v, "debug." .. k)
                end
            else
                env.debug[k] = v
            end
        end
    end

    -- Self-references
    env._G   = env
    env._ENV = env

    return env
end

-- ============================================================================
-- STAGE 12: FILE OUTPUT ENGINE (createfile)
-- ============================================================================

local FileOutput = {}

function FileOutput.ensureFolder(folder)
    folder = folder or Config.Output.Folder
    if not _createfile and not _writefile then return false end

    if _isfolder and _makefolder then
        if not _isfolder(folder) then
            _pcall(_makefolder, folder)
        end
        return _isfolder(folder)
    end
    return true -- assume it works
end

--- Creates a file in the workspace folder using createfile (or writefile fallback)
function FileOutput.create(filename, content)
    local writeFunc = _createfile or _writefile
    if not writeFunc then
        _warn("[EnvLogger] No file write function available (createfile/writefile)")
        return false
    end

    FileOutput.ensureFolder()

    local path = Config.Output.Folder .. "/" .. filename
    local ok, err = _pcall(writeFunc, path, content)
    if ok then
        _print("[EnvLogger] Created file: " .. path)
    else
        -- Try without folder prefix
        ok, err = _pcall(writeFunc, filename, content)
        if ok then
            _print("[EnvLogger] Created file: " .. filename)
        else
            _warn("[EnvLogger] Failed to create file: " .. _tostring(err))
        end
    end
    return ok
end

--- Saves all results to files
function FileOutput.saveAll(prefix)
    if not Config.Output.Enabled then return end

    prefix = prefix or ""
    if Config.Output.TimestampFiles then
        local ts = _tostring(_math.floor(_os_clock()))
        prefix = prefix .. (prefix ~= "" and "_" or "") .. ts
    end

    -- Ensure subfolder
    if Config.Output.CreateSubfolders then
        FileOutput.ensureFolder(Config.Output.Folder)
    end

    -- 1. Reconstructed source
    if Config.Output.SaveReconstructed then
        FileOutput.create(prefix .. "_reconstructed.lua", Reconstructor.reconstruct())
    end

    -- 2. Summary
    if Config.Output.SaveSummary then
        FileOutput.create(prefix .. "_summary.txt", Reconstructor.summary())
    end

    -- 3. Raw operation log
    if Config.Output.SaveOperationLog then
        local logLines = {}
        local maxLog = _math.min(Log.count, 100000) -- cap raw log file
        for i = 1, maxLog do
            _table.insert(logLines, _string.format("[%06d|%.3fs] %s",
                i, Log.entries[i].time, Serializer.opToString(Log.entries[i])))
        end
        if Log.count > maxLog then
            _table.insert(logLines, _string.format("\n... truncated (%d total ops)", Log.count))
        end
        FileOutput.create(prefix .. "_operations.log", _table.concat(logLines, "\n"))
    end

    -- 4. Remotes
    if Config.Output.SaveRemotes and #Log.remotesCaptured > 0 then
        local remoteLines = {}
        for _, r in _ipairs(Log.remotesCaptured) do
            _table.insert(remoteLines, _string.format("[%.3fs] %s:%s(%s)",
                r.time or 0, r.path or r.name or "?", r.method or "?",
                Serializer.serializeArgs(r.args or {}, r.args and r.args.n or 0)))
        end
        FileOutput.create(prefix .. "_remotes.log", _table.concat(remoteLines, "\n"))
    end

    -- 5. URLs
    if Config.Output.SaveUrls then
        local urlCount = 0
        for url, content in _pairs(Log.urlsDiscovered) do
            urlCount = urlCount + 1
            local safeName = _string.gsub(url, "[^%w]", "_")
            safeName = _string.sub(safeName, 1, 80)
            FileOutput.create(prefix .. "_url_" .. urlCount .. "_" .. safeName .. ".lua", content)
        end
    end

    -- 6. Traced scripts
    for idx, script in _ipairs(Log.scriptsLoaded) do
        FileOutput.create(prefix .. _string.format("_script_%03d.lua", idx), script.code or "")
    end

    -- 7. VM analysis
    if Config.Output.SaveVMAnalysis and Config.VM.Enabled then
        FileOutput.create(prefix .. "_vm_analysis.txt", VMAnalyzer.report())
    end

    -- 8. Closure analysis
    if Config.Output.SaveClosures then
        local closureLines = {}
        for fn, info in _pairs(Log.closureMap) do
            _table.insert(closureLines, _string.format("=== %s ===", info.name or "?"))
            if info.source then
                _table.insert(closureLines, "  Source: " .. _tostring(info.source))
            end
            if info.lineDefined then
                _table.insert(closureLines, "  Line: " .. _tostring(info.lineDefined))
            end
            if info.upvalues then
                for idx, uv in _pairs(info.upvalues) do
                    _table.insert(closureLines, _string.format("  Upvalue[%d] = %s", idx, Serializer.serialize(uv)))
                end
            end
            if info.constants then
                for idx, c in _pairs(info.constants) do
                    _table.insert(closureLines, _string.format("  Constant[%d] = %s", idx, Serializer.serialize(c)))
                end
            end
            if info.decompiled then
                _table.insert(closureLines, "  Decompiled:")
                _table.insert(closureLines, info.decompiled)
            end
            _table.insert(closureLines, "")
        end
        if #closureLines > 0 then
            FileOutput.create(prefix .. "_closures.txt", _table.concat(closureLines, "\n"))
        end
    end

    -- 9. Decrypted strings
    if #Log.stringsDecrypted > 0 then
        local strLines = {}
        for _, s in _ipairs(Log.stringsDecrypted) do
            _table.insert(strLines, _string.format("[%s] %s", s.method or "?", s.result or ""))
        end
        FileOutput.create(prefix .. "_decrypted_strings.txt", _table.concat(strLines, "\n"))
    end

    _print("[EnvLogger] All files saved with prefix: " .. prefix)
end

-- ============================================================================
-- STAGE 13: WEBHOOK ENGINE
-- ============================================================================

local Webhook = {}
local _lastWebhookSend = 0

function Webhook.send(content, embeds)
    if not Config.Webhook.Enabled or not Config.Webhook.Url or Config.Webhook.Url == "" then
        return false
    end
    if not _request then return false, "no request function" end

    local now = _os_clock() * 1000
    if now - _lastWebhookSend < Config.Webhook.RateLimitMs then
        _task_wait(Config.Webhook.RateLimitMs / 1000)
    end
    _lastWebhookSend = _os_clock() * 1000

    local payload = {
        username   = Config.Webhook.Username,
        avatar_url = Config.Webhook.AvatarUrl ~= "" and Config.Webhook.AvatarUrl or nil,
    }
    if content then payload.content = _string.sub(content, 1, 2000) end
    if embeds  then payload.embeds  = embeds end

    local jsonBody
    if _HttpService then
        jsonBody = _HttpService:JSONEncode(payload)
    else
        jsonBody = Webhook.toJson(payload)
    end

    local ok, result = _pcall(_request, {
        Url     = Config.Webhook.Url,
        Method  = "POST",
        Headers = { ["Content-Type"] = "application/json" },
        Body    = jsonBody,
    })
    return ok, result
end

function Webhook.sendChunked(title, content, codeBlock, color)
    if not content or #content == 0 then return end
    local chunkSize   = Config.Webhook.ChunkSize
    local totalChunks = _math.ceil(#content / chunkSize)

    Webhook.send(nil, {{
        title       = title,
        description = _string.format("Size: %d bytes | Chunks: %d", #content, totalChunks),
        color       = color or Config.Webhook.Color.Info,
        footer      = { text = "Env Logger v5.0.0 | " .. Config.ExecutorName },
    }})
    _task_wait(1.2)

    for i = 1, totalChunks do
        local s = (i - 1) * chunkSize + 1
        local e = _math.min(i * chunkSize, #content)
        local chunk = _string.sub(content, s, e)

        if codeBlock then chunk = "```lua\n" .. chunk .. "\n```" end
        Webhook.send(_string.format("**[%d/%d]**\n%s", i, totalChunks, chunk))
        if i < totalChunks then _task_wait(1.2) end
    end
end

function Webhook.sendResults()
    if not Config.Webhook.Enabled then return end

    -- Header
    local urlCount = 0
    for _ in _pairs(Log.urlsDiscovered) do urlCount = urlCount + 1 end

    Webhook.send(nil, {{
        title = "🔬 Env Logger v5.0.0 — Analysis Results",
        description = _string.format(
            "**Executor:** %s\n**Operations:** %d / %d\n**URLs:** %d\n**Remotes:** %d\n**Scripts:** %d\n**Runtime:** %.3fs",
            Config.ExecutorName, Log.count, Config.MaxLogEntries,
            urlCount, #Log.remotesCaptured, #Log.scriptsLoaded,
            _os_clock() - Log.startTime
        ),
        color = Config.Webhook.Color.Info,
    }})
    _task_wait(1.5)

    -- Summary
    if Config.Webhook.SendSummary then
        Webhook.sendChunked("📊 Summary", Reconstructor.summary(), false, Config.Webhook.Color.Info)
        _task_wait(1.5)
    end

    -- Reconstructed source
    if Config.Webhook.SendSource then
        Webhook.sendChunked("📝 Reconstructed Source", Reconstructor.reconstruct(), true, Config.Webhook.Color.Success)
        _task_wait(1.5)
    end

    -- URLs
    if Config.Webhook.SendUrls and urlCount > 0 then
        local urlLines = {}
        for url, content in _pairs(Log.urlsDiscovered) do
            _table.insert(urlLines, _string.format("• `%s` (%d bytes, lua: %s)",
                url, #content, _tostring(UrlEngine.looksLikeLua(content))))
        end
        Webhook.send(nil, {{
            title       = "🔗 Discovered URLs (" .. urlCount .. ")",
            description = _string.sub(_table.concat(urlLines, "\n"), 1, 4000),
            color       = Config.Webhook.Color.Warning,
        }})
        _task_wait(1.5)

        for url, content in _pairs(Log.urlsDiscovered) do
            if UrlEngine.looksLikeLua(content) then
                Webhook.sendChunked("🔓 URL: " .. _string.sub(url, 1, 100), content, true)
                _task_wait(1.5)
            end
        end
    end

    -- Remotes
    if Config.Webhook.SendRemotes and #Log.remotesCaptured > 0 then
        local rLines = {}
        for i, r in _ipairs(Log.remotesCaptured) do
            if i > 100 then
                _table.insert(rLines, "... +" .. (#Log.remotesCaptured - 100) .. " more")
                break
            end
            _table.insert(rLines, _string.format("[%.3fs] `%s` **%s** args: %s",
                r.time or 0, r.path or r.name or "?", r.method or "?",
                Serializer.serializeArgs(r.args or {}, r.args and r.args.n or 0)))
        end
        Webhook.send(nil, {{
            title       = "📡 Captured Remotes (" .. #Log.remotesCaptured .. ")",
            description = _string.sub(_table.concat(rLines, "\n"), 1, 4000),
            color       = Config.Webhook.Color.Error,
        }})
        _task_wait(1.5)
    end

    -- VM Analysis
    if Config.Webhook.SendVMAnalysis and Config.VM.Enabled then
        local vmReport = VMAnalyzer.report()
        if #vmReport > 50 then
            Webhook.sendChunked("🤖 VM Analysis", vmReport, true, Config.Webhook.Color.VM)
            _task_wait(1.5)
        end
    end

    -- Decrypted strings
    if #Log.stringsDecrypted > 0 then
        local sLines = {}
        for _, s in _ipairs(Log.stringsDecrypted) do
            _table.insert(sLines, _string.format("[%s] `%s`", s.method or "?",
                _string.sub(s.result or "", 1, 200)))
        end
        Webhook.send(nil, {{
            title       = "🔤 Decrypted Strings (" .. #Log.stringsDecrypted .. ")",
            description = _string.sub(_table.concat(sLines, "\n"), 1, 4000),
            color       = Config.Webhook.Color.VM,
        }})
        _task_wait(1.5)
    end

    -- Raw log
    if Config.Webhook.SendLog then
        local logLines = {}
        local maxSend = _math.min(Log.count, 300)
        for i = 1, maxSend do
            _table.insert(logLines, _string.format("[%05d] %s", i, Serializer.opToString(Log.entries[i])))
        end
        if Log.count > maxSend then
            _table.insert(logLines, _string.format("... +%d more ops", Log.count - maxSend))
        end
        Webhook.sendChunked("📋 Operation Log", _table.concat(logLines, "\n"), true)
        _task_wait(1.5)
    end

    -- Final
    Webhook.send(nil, {{
        title       = "✅ Analysis Complete",
        description = _string.format(
            "Total operations: **%d**\nURLs: **%d**\nRemotes: **%d**\nScripts: **%d**\nDecrypted strings: **%d**\nVM opcodes: **%d**\nErrors: **%d**\nBlocked ops: **%d**\nRuntime: **%.3fs**",
            Log.count, urlCount, #Log.remotesCaptured, #Log.scriptsLoaded,
            #Log.stringsDecrypted, #Log.vmOpcodes, #Log.errorsLogged,
            #Log.blockedOperations, _os_clock() - Log.startTime
        ),
        color = Config.Webhook.Color.Success,
    }})
end

--- Minimal JSON encoder
function Webhook.toJson(obj)
    local t = _type(obj)
    if t == "nil" then return "null"
    elseif t == "boolean" then return _tostring(obj)
    elseif t == "number" then return _tostring(obj)
    elseif t == "string" then
        local e = _string.gsub(obj, '[\\"]', function(c) return '\\' .. c end)
        e = _string.gsub(e, "\n", "\\n")
        e = _string.gsub(e, "\r", "\\r")
        e = _string.gsub(e, "\t", "\\t")
        return '"' .. e .. '"'
    elseif t == "table" then
        local isArr = true
        local n = 0
        for k in _pairs(obj) do
            n = n + 1
            if _type(k) ~= "number" or k ~= n then isArr = false; break end
        end
        if isArr then
            local p = {}
            for _, v in _ipairs(obj) do _table.insert(p, Webhook.toJson(v)) end
            return "[" .. _table.concat(p, ",") .. "]"
        else
            local p = {}
            for k, v in _pairs(obj) do
                if v ~= nil then
                    _table.insert(p, Webhook.toJson(_tostring(k)) .. ":" .. Webhook.toJson(v))
                end
            end
            return "{" .. _table.concat(p, ",") .. "}"
        end
    end
    return "null"
end

-- ============================================================================
-- STAGE 14: RECONSTRUCTOR
-- ============================================================================

local Reconstructor = {}

function Reconstructor.reconstruct()
    local lines    = {}
    local varMap   = {}
    local varCtr   = 0
    local declared = {}

    local function add(text)  _table.insert(lines, text) end

    local function getVar(obj, hint)
        if obj == nil then return "nil" end
        local t = _type(obj)
        if t == "string"  then return Serializer.serializeString(obj) end
        if t == "number" or t == "boolean" then return _tostring(obj) end

        local id = _objectIds[obj]
        if id and varMap[id] then return varMap[id] end

        local name = _objectNames[obj]
        if name then
            name = _string.gsub(name, "[^%w_]", "_")
            name = _string.gsub(name, "__+", "_")
            name = _string.gsub(name, "^_", "")
            if #name == 0 or _string.match(name, "^%d") then name = "v_" .. name end
        else
            varCtr = varCtr + 1
            name = "var" .. varCtr
        end
        if id then varMap[id] = name end
        return name
    end

    local function fmtPath(target, key)
        local tn = getVar(target)
        if _type(key) == "string" and _string.match(key, "^[%a_][%w_]*$") then
            return tn .. "." .. key
        end
        return tn .. "[" .. Serializer.serialize(key) .. "]"
    end

    -- Header
    add("--[[ ════════════════════════════════════════════════════════════ ]]")
    add("--[[   RECONSTRUCTED BY ENV LOGGER v5.0.0                        ]]")
    add(_string.format("--[[   Operations: %d | Runtime: %.3fs                          ]]",
        Log.count, Log.count > 0 and Log.entries[Log.count].time or 0))

    local urlCount = 0
    for _ in _pairs(Log.urlsDiscovered) do urlCount = urlCount + 1 end
    add(_string.format("--[[   URLs: %d | Remotes: %d | Scripts: %d                    ]]",
        urlCount, #Log.remotesCaptured, #Log.scriptsLoaded))
    add(_string.format("--[[   VM Opcodes: %d | Strings Decrypted: %d                 ]]",
        #Log.vmOpcodes, #Log.stringsDecrypted))
    add(_string.format("--[[   Executor: %-40s            ]]", Config.ExecutorName))

    -- VM identification
    if #Log.vmIdentification > 0 then
        add(_string.format("--[[   Obfuscator: %s (confidence: %d%%)                     ]]",
            Log.vmIdentification[1].name, Log.vmIdentification[1].confidence))
    end
    add("--[[ ════════════════════════════════════════════════════════════ ]]")
    add("")

    -- Discovered URLs section
    if urlCount > 0 then
        add("-- ═══════════════════════════════════════")
        add("-- DISCOVERED URLs")
        add("-- ═══════════════════════════════════════")
        for url, content in _pairs(Log.urlsDiscovered) do
            add(_string.format('-- [URL] %s (%d bytes, lua=%s)', url, #content,
                _tostring(UrlEngine.looksLikeLua(content))))
        end
        add("")
    end

    -- Remotes section
    if #Log.remotesCaptured > 0 then
        add("-- ═══════════════════════════════════════")
        add("-- CAPTURED REMOTES")
        add("-- ═══════════════════════════════════════")
        local seenRemotes = {}
        for _, r in _ipairs(Log.remotesCaptured) do
            local key = (r.path or "?") .. ":" .. (r.method or "?")
            seenRemotes[key] = (seenRemotes[key] or 0) + 1
        end
        for key, cnt in _pairs(seenRemotes) do
            add(_string.format("-- %s (x%d)", key, cnt))
        end
        add("")
        -- First 50 with args
        for i, r in _ipairs(Log.remotesCaptured) do
            if i > 50 then add("-- ... and more"); break end
            add(_string.format("-- [%.3fs] %s:%s(%s)",
                r.time or 0, r.path or r.name or "?", r.method or "?",
                Serializer.serializeArgs(r.args or {}, r.args and r.args.n or 0)))
        end
        add("")
    end

    -- Decrypted strings section
    if #Log.stringsDecrypted > 0 then
        add("-- ═══════════════════════════════════════")
        add("-- DECRYPTED STRINGS")
        add("-- ═══════════════════════════════════════")
        for _, s in _ipairs(Log.stringsDecrypted) do
            add(_string.format('-- [%s] %s', s.method or "?",
                Serializer.serializeString(s.result or "")))
        end
        add("")
    end

    -- Main reconstruction
    add("-- ═══════════════════════════════════════")
    add("-- RECONSTRUCTED CODE")
    add("-- ═══════════════════════════════════════")
    add("")

    for idx = 1, Log.count do
        local entry = Log.entries[idx]
        local op    = entry.op

        if op == OpCodes.CALL then
            local fn   = getVar(entry.func)
            local args = Serializer.serializeArgs(entry.args or {}, entry.argc or 0)

            if entry.err then
                add(_string.format("-- ERROR: %s(%s) => %s", fn, args, _tostring(entry.err)))
            elseif entry.retc and entry.retc > 0 then
                local retParts = {}
                for r = 1, entry.retc do
                    local ret = entry.rets and entry.rets[r]
                    if ret ~= nil and (_type(ret) == "table" or _type(ret) == "function" or _type(ret) == "userdata") then
                        _table.insert(retParts, getVar(ret))
                    else
                        _table.insert(retParts, Serializer.serialize(ret))
                    end
                end
                local retStr = _table.concat(retParts, ", ")
                local decl = declared[retStr] and "" or "local "
                declared[retStr] = true
                add(_string.format("%s%s = %s(%s)", decl, retStr, fn, args))
            else
                add(_string.format("%s(%s)", fn, args))
            end

        elseif op == OpCodes.INDEX then
            local path = fmtPath(entry.target, entry.key)
            if not Config.CollapseChains then
                add(_string.format("-- read: %s => %s", path, Serializer.serialize(entry.value)))
            else
                local nxt = Log.entries[idx + 1]
                if not nxt or (nxt.op ~= OpCodes.CALL and nxt.op ~= OpCodes.NAMECALL and nxt.op ~= OpCodes.INDEX) then
                    add(_string.format("local _ = %s  -- %s", path, Serializer.serialize(entry.value)))
                end
            end

        elseif op == OpCodes.NEWINDEX then
            add(_string.format("%s = %s", fmtPath(entry.target, entry.key), Serializer.serialize(entry.value)))

        elseif op == OpCodes.NAMECALL then
            local tn   = getVar(entry.target)
            local args = Serializer.serializeArgs(entry.args or {}, entry.argc or 0)
            if entry.retc and entry.retc > 0 then
                add(_string.format("local result = %s:%s(%s)  -- => %s",
                    tn, entry.method or "?", args,
                    Serializer.serializeArgs(entry.rets or {}, entry.retc)))
            else
                add(_string.format("%s:%s(%s)", tn, entry.method or "?", args))
            end

        elseif op == OpCodes.REMOTE_FIRE then
            add(_string.format("-- [REMOTE:FireServer] %s(%s)",
                _tostring(entry.path or entry.name or "?"),
                Serializer.serializeArgs(entry.args or {}, entry.argc or 0)))

        elseif op == OpCodes.REMOTE_INVOKE then
            add(_string.format("-- [REMOTE:InvokeServer] %s(%s)",
                _tostring(entry.path or entry.name or "?"),
                Serializer.serializeArgs(entry.args or {}, entry.argc or 0)))

        elseif op == OpCodes.CONCAT then
            add(_string.format("local _ = %s .. %s",
                Serializer.serialize(entry.left), Serializer.serialize(entry.right)))

        elseif op == OpCodes.ARITH then
            local syms = { add="+", sub="-", mul="*", div="/", mod="%%", pow="^", unm="-", idiv="//" }
            add(_string.format("local _ = %s %s %s",
                Serializer.serialize(entry.left),
                syms[entry.arithOp] or "?",
                Serializer.serialize(entry.right)))

        elseif op == OpCodes.COMPARE then
            add(_string.format("-- cmp: %s %s %s",
                Serializer.serialize(entry.left), entry.cmp or "?", Serializer.serialize(entry.right)))

        elseif op == OpCodes.LOADSTRING then
            add(_string.format("local fn = loadstring(--[[%d bytes]] %s)",
                entry.codeLength or 0,
                Serializer.serializeString(_string.sub(entry.code or "", 1, 100))))

        elseif op == OpCodes.HTTP_FETCH then
            add(_string.format('-- [HTTP %s] %s (status:%s size:%s)',
                _tostring(entry.httpMethod or "GET"),
                Serializer.serialize(entry.url),
                _tostring(entry.status or "?"),
                _tostring(entry.size or "?")))

        elseif op == OpCodes.DEOBF_URL then
            add(_string.format("-- [DEOBF URL] %s (depth:%d)",
                Serializer.serialize(entry.url), entry.depth or 0))

        elseif op == OpCodes.REQUIRE then
            add(_string.format("local module = require(%s)", Serializer.serialize(entry.target)))

        elseif op == OpCodes.METATABLE then
            if entry.kind == "set" then
                add(_string.format("setmetatable(%s, %s)", getVar(entry.target), Serializer.serialize(entry.metatable)))
            else
                add(_string.format("local mt = getmetatable(%s)", getVar(entry.target)))
            end

        elseif op == OpCodes.GETFENV then
            add(_string.format("local env = getfenv(%s)", Serializer.serialize(entry.level)))

        elseif op == OpCodes.SETFENV then
            add("-- setfenv intercepted")

        elseif op == OpCodes.VM_OPCODE then
            add(_string.format("-- [VM OP] %s A=%s B=%s C=%s",
                _tostring(entry.opname or entry.opcode or "?"),
                _tostring(entry.A or ""), _tostring(entry.B or ""), _tostring(entry.C or "")))

        elseif op == OpCodes.VM_IDENTIFIED then
            add(_string.format("-- [VM IDENTIFIED] %s (confidence: %d%%)",
                _tostring(entry.obfuscator), entry.confidence or 0))

        elseif op == OpCodes.VM_STRING_DECRYPT then
            add(_string.format("-- [DECRYPTED via %s] %s",
                _tostring(entry.method), Serializer.serialize(entry.decrypted)))

        elseif op == OpCodes.VM_LOOP then
            add(_string.format("-- [VM DISPATCH LOOP] %s (%d calls)",
                _tostring(entry.funcName), entry.callCount or 0))

        elseif op == OpCodes.BLOCKED then
            add(_string.format("-- [BLOCKED] %s", entry.text or entry.action or ""))

        elseif op == OpCodes.ERROR_CAUGHT then
            add(_string.format("-- [ERROR] %s", _tostring(entry.message)))

        elseif op == OpCodes.UPVALUE then
            add(_string.format("-- upvalue[%d] of %s = %s",
                entry.index or 0, entry.funcName or "?", Serializer.serialize(entry.value)))

        elseif op == OpCodes.CONSTANT then
            add(_string.format("-- constant[%d] of %s = %s",
                entry.index or 0, entry.funcName or "?", Serializer.serialize(entry.value)))

        elseif op == OpCodes.COMMENT then
            add("-- " .. (entry.text or ""))

        elseif op == OpCodes.ITERATOR then
            add(_string.format("for k, v in %s(%s) do ... end", entry.kind or "pairs", getVar(entry.target)))

        elseif op == OpCodes.LEN then
            add(_string.format("local _ = #%s", getVar(entry.target)))

        elseif op == OpCodes.RAWOP then
            add(_string.format("%s(%s, %s)",
                entry.kind or "rawop", getVar(entry.target), Serializer.serialize(entry.key)))

        elseif op == OpCodes.CLIPBOARD then
            add(_string.format("--%sclipboard(%s)",
                entry.action == "set" and "set" or "get",
                Serializer.serialize(entry.text)))

        elseif op == OpCodes.GC_SCAN then
            add("-- [GC SCAN] " .. (entry.text or ""))

        elseif op == OpCodes.COROUTINE_OP then
            add("-- [COROUTINE] " .. Serializer.opToString(entry))

        else
            -- Generic
            add("-- " .. Serializer.opToString(entry))
        end
    end

    -- Append deobfuscated URL contents at the bottom
    for url, content in _pairs(Log.urlsDiscovered) do
        if UrlEngine.looksLikeLua(content) then
            add("")
            add("-- ═══════════════════════════════════════")
            add(_string.format("-- DEOBFUSCATED URL: %s", url))
            add("-- ═══════════════════════════════════════")
            local contentLines = {}
            for line in _string.gmatch(content .. "\n", "(.-)\n") do
                _table.insert(contentLines, line)
            end
            for _, line in _ipairs(contentLines) do add(line) end
        end
    end

    add("")
    add("-- [END OF RECONSTRUCTION]")
    return _table.concat(lines, "\n")
end

function Reconstructor.summary()
    local opCounts   = {}
    local funcCalls  = {}
    local indexPaths = {}

    for i = 1, Log.count do
        local e = Log.entries[i]
        opCounts[e.op] = (opCounts[e.op] or 0) + 1
        if e.op == OpCodes.CALL and e.func then
            local name = _objectNames[e.func] or _tostring(e.func)
            funcCalls[name] = (funcCalls[name] or 0) + 1
        end
        if e.op == OpCodes.INDEX and e.target then
            local path = (_objectNames[e.target] or "?") .. "." .. _tostring(e.key)
            indexPaths[path] = (indexPaths[path] or 0) + 1
        end
    end

    local L = {}
    local function a(s) _table.insert(L, s) end

    a("╔══════════════════════════════════════════════════════════════╗")
    a("║              ENV LOGGER v5.0.0 — ANALYSIS SUMMARY           ║")
    a("╚══════════════════════════════════════════════════════════════╝")
    a("")
    a(_string.format("  Executor:             %s", Config.ExecutorName))
    a(_string.format("  Total operations:     %d / %d", Log.count, Config.MaxLogEntries))
    a(_string.format("  Runtime:              %.3fs", Log.count > 0 and Log.entries[Log.count].time or 0))

    local urlCount = 0
    for _ in _pairs(Log.urlsDiscovered) do urlCount = urlCount + 1 end
    a(_string.format("  URLs discovered:      %d", urlCount))
    a(_string.format("  Remotes captured:     %d", #Log.remotesCaptured))
    a(_string.format("  Scripts traced:       %d", #Log.scriptsLoaded))
    a(_string.format("  Closures analyzed:    %d",
        (function() local c=0; for _ in _pairs(Log.closureMap) do c=c+1 end; return c end)()))
    a(_string.format("  Strings decrypted:    %d", #Log.stringsDecrypted))
    a(_string.format("  VM opcodes captured:  %d", #Log.vmOpcodes))
    a(_string.format("  Errors caught:        %d", #Log.errorsLogged))
    a(_string.format("  Blocked operations:   %d", #Log.blockedOperations))
    a("")

    -- VM identification
    if #Log.vmIdentification > 0 then
        a("─── Obfuscator Identification ───")
        for _, r in _ipairs(Log.vmIdentification) do
            local bar = _string.rep("█", _math.min(r.confidence, 50))
            a(_string.format("  %-20s %s (%d%%)", r.name, bar, r.confidence))
        end
        a("")
    end

    a("─── Operation Breakdown ───")
    local sortedOps = {}
    for op, count in _pairs(opCounts) do _table.insert(sortedOps, {op=op, count=count}) end
    _table.sort(sortedOps, function(a,b) return a.count > b.count end)
    for _, e in _ipairs(sortedOps) do
        local pct = (e.count / Log.count) * 100
        a(_string.format("  %-25s %8d  (%5.1f%%)", e.op, e.count, pct))
    end
    a("")

    a("─── Top Function Calls ───")
    local sortedCalls = {}
    for name, count in _pairs(funcCalls) do _table.insert(sortedCalls, {name=name, count=count}) end
    _table.sort(sortedCalls, function(a,b) return a.count > b.count end)
    for i = 1, _math.min(#sortedCalls, 40) do
        a(_string.format("  %-50s %8d", sortedCalls[i].name, sortedCalls[i].count))
    end
    a("")

    a("─── Top Indexed Paths ───")
    local sortedPaths = {}
    for path, count in _pairs(indexPaths) do _table.insert(sortedPaths, {path=path, count=count}) end
    _table.sort(sortedPaths, function(a,b) return a.count > b.count end)
    for i = 1, _math.min(#sortedPaths, 40) do
        a(_string.format("  %-60s %8d", sortedPaths[i].path, sortedPaths[i].count))
    end
    a("")

    -- URLs
    if urlCount > 0 then
        a("─── Discovered URLs ───")
        for url, content in _pairs(Log.urlsDiscovered) do
            a(_string.format("  %s", url))
            a(_string.format("    Size: %d | Lua: %s", #content, _tostring(UrlEngine.looksLikeLua(content))))
        end
        a("")
    end

    -- Remotes summary
    if #Log.remotesCaptured > 0 then
        a("─── Captured Remotes ───")
        local seenR = {}
        for _, r in _ipairs(Log.remotesCaptured) do
            local key = (r.path or "?") .. ":" .. (r.method or "?")
            seenR[key] = (seenR[key] or 0) + 1
        end
        for key, cnt in _pairs(seenR) do
            a(_string.format("  %-65s x%d", key, cnt))
        end
        a("")
    end

    -- Errors
    if #Log.errorsLogged > 0 then
        a("─── Errors ───")
        for i, err in _ipairs(Log.errorsLogged) do
            if i > 20 then a("  ... and " .. (#Log.errorsLogged - 20) .. " more"); break end
            a(_string.format("  [%.3fs] %s", err.time or 0, _tostring(err.message)))
        end
        a("")
    end

    return _table.concat(L, "\n")
end

-- ============================================================================
-- STAGE 15: AUTO-SAVE DAEMON
-- ============================================================================

local AutoSave = {}
local _autoSaveRunning = false

function AutoSave.start()
    if not Config.Output.AutoSave or not Config.HasFileSystem then return end
    if _autoSaveRunning then return end
    _autoSaveRunning = true

    _task_spawn(function()
        while _autoSaveRunning do
            _task_wait(Config.Output.AutoSaveInterval)
            if Log.count > 0 then
                _pcall(function()
                    FileOutput.create("autosave_latest.lua", Reconstructor.reconstruct())
                end)
            end
        end
    end)
end

function AutoSave.stop()
    _autoSaveRunning = false
end

-- ============================================================================
-- STAGE 16: MAIN API
-- ============================================================================

local EnvLogger = {}

function EnvLogger.init(options)
    if options then
        for k, v in _pairs(options) do
            if k == "Webhook" and _type(v) == "table" then
                for wk, wv in _pairs(v) do Config.Webhook[wk] = wv end
            elseif k == "VM" and _type(v) == "table" then
                for vk, vv in _pairs(v) do Config.VM[vk] = vv end
            elseif k == "Output" and _type(v) == "table" then
                for ok_, ov in _pairs(v) do Config.Output[ok_] = ov end
            elseif Config[k] ~= nil then
                Config[k] = v
            end
        end
    end

    Log.record(OpCodes.COMMENT, {
        text = _string.format("Env Logger v5.0.0 initialized | Executor: %s | Max Log: %d",
            Config.ExecutorName, Config.MaxLogEntries)
    })

    -- Install hooks
    if Config.HookNamecall and Config.IsRoblox then
        _pcall(NamecallHook.install)
    end

    -- Start auto-save
    AutoSave.start()

    return EnvLogger
end

--- Execute obfuscated code string or function
function EnvLogger.execute(code, envOverrides)
    local baseEnv = _getfenv and _getfenv(0) or _ENV or {}
    local hookedEnv = Hooker.buildEnvironment(baseEnv)

    if envOverrides then
        for k, v in _pairs(envOverrides) do hookedEnv[k] = v end
    end

    -- Compile
    local fn
    if _type(code) == "string" then
        -- Pre-analysis
        if Config.DeobfuscateUrls then
            local urls = UrlEngine.extractUrls(code)
            for _, url in _ipairs(urls) do
                _task_spawn(function() UrlEngine.deobfuscateUrl(url) end)
            end
        end
        if Config.VM.Enabled and Config.VM.IdentifyObfuscator then
            VMAnalyzer.identify(code)
        end

        local err
        fn, err = _loadstring(code)
        if not fn then return false, "Compilation error: " .. _tostring(err) end
    elseif _type(code) == "function" then
        fn = code
    else
        return false, "Expected string or function, got " .. _type(code)
    end

    -- Set hooked environment
    if _setfenv then _setfenv(fn, hookedEnv) end

    -- Pre-execution analysis
    if Config.CaptureClosureUpvalues then
        _pcall(function()
            ClosureAnalyzer.analyze(fn, "main_chunk")
            if Config.VM.FollowClosureChains then
                VMAnalyzer.analyzeClosureChain(fn)
            end
        end)
    end

    Log.record(OpCodes.COMMENT, { text = "══════ EXECUTION STARTED ══════" })
    local startTime = _os_clock()

    local results = _pack(_pcall(fn))

    local elapsed = _os_clock() - startTime
    Log.record(OpCodes.COMMENT, {
        text = _string.format("══════ EXECUTION FINISHED ══════ (%.3fs, success: %s)", elapsed, _tostring(results[1]))
    })

    if not results[1] then
        _table.insert(Log.errorsLogged, { message = results[2], time = elapsed })
        Log.record(OpCodes.ERROR_CAUGHT, { message = results[2] })
    end

    return results[1], _select(2, _unpack(results, 1, results.n))
end

--- Execute from URL
function EnvLogger.executeUrl(url, envOverrides)
    Log.record(OpCodes.COMMENT, { text = "Fetching: " .. _tostring(url) })
    local content, status = UrlEngine.deobfuscateUrl(url)
    if not content then return false, "Fetch failed: " .. _tostring(status) end
    Log.record(OpCodes.COMMENT, { text = _string.format("Fetched %d bytes (status:%s)", #content, _tostring(status)) })
    return EnvLogger.execute(content, envOverrides)
end

--- Analyze URL without executing
function EnvLogger.analyzeUrl(url)
    Log.record(OpCodes.COMMENT, { text = "Analyzing URL: " .. _tostring(url) })
    local content, status = UrlEngine.deobfuscateUrl(url)
    if not content then return nil, "Fetch failed: " .. _tostring(status) end

    -- Recursive URL discovery
    local allUrls = { url }
    local function extractRec(str, depth)
        if depth > 5 then return end
        for _, u in _ipairs(UrlEngine.extractUrls(str)) do
            if not Log.urlsDiscovered[u] then
                _table.insert(allUrls, u)
                local inner = UrlEngine.fetch(u)
                if inner then
                    Log.urlsDiscovered[u] = inner
                    extractRec(inner, depth + 1)
                end
            end
        end
    end
    extractRec(content, 0)

    -- Compile + analyze without executing
    if UrlEngine.looksLikeLua(content) then
        local ok, fn = _pcall(_loadstring, content)
        if ok and fn then
            ClosureAnalyzer.analyze(fn, "url:" .. url)
            VMAnalyzer.analyzeClosureChain(fn)
        end
    end

    return {
        url        = url,
        content    = content,
        size       = #content,
        isLua      = UrlEngine.looksLikeLua(content),
        nestedUrls = allUrls,
        status     = status,
        vmId       = Log.vmIdentification,
    }
end

--- GC scan
function EnvLogger.scanClosures()    return ClosureAnalyzer.scanGC() end
function EnvLogger.scanRegistry()    return ClosureAnalyzer.scanRegistry() end

-- ═════ Output methods ═════

function EnvLogger.getLog()                   return Log.entries end
function EnvLogger.getCount()                  return Log.count end
function EnvLogger.getDiscoveredUrls()         return Log.urlsDiscovered end
function EnvLogger.getCapturedRemotes()        return Log.remotesCaptured end
function EnvLogger.getTracedScripts()          return Log.scriptsLoaded end
function EnvLogger.getErrors()                 return Log.errorsLogged end
function EnvLogger.getDecryptedStrings()       return Log.stringsDecrypted end
function EnvLogger.getVMOpcodes()              return Log.vmOpcodes end
function EnvLogger.getVMIdentification()       return Log.vmIdentification end
function EnvLogger.getBlockedOperations()      return Log.blockedOperations end
function EnvLogger.getReconstructedSource()    return Reconstructor.reconstruct() end
function EnvLogger.getSummary()                return Reconstructor.summary() end
function EnvLogger.getVMReport()               return VMAnalyzer.report() end

function EnvLogger.output(filePrefix)
    local summary = Reconstructor.summary()
    local source  = Reconstructor.reconstruct()

    _print(summary)
    _print(_string.rep("═", 60))

    -- Save files using createfile
    if Config.HasFileSystem then
        FileOutput.saveAll(filePrefix or "envlogger")
    end

    -- Send to webhook
    if Config.Webhook.Enabled then
        _task_spawn(function()
            Webhook.sendResults()
        end)
    end

    return summary .. "\n\n" .. source
end

--- One-liner: execute + full output
function EnvLogger.run(code, outputPrefix)
    EnvLogger.reset()
    local success, err = EnvLogger.execute(code)
    if not success then
        _warn("[EnvLogger] Execution error: " .. _tostring(err))
    end
    return EnvLogger.output(outputPrefix or "envlogger_run")
end

--- One-liner: fetch URL + execute + full output
function EnvLogger.runUrl(url, outputPrefix)
    EnvLogger.reset()
    local success, err = EnvLogger.executeUrl(url)
    if not success then
        _warn("[EnvLogger] Execution error: " .. _tostring(err))
    end
    return EnvLogger.output(outputPrefix or "envlogger_url")
end

--- Analyze URL only + output
function EnvLogger.analyzeAndOutput(url, outputPrefix)
    EnvLogger.reset()
    EnvLogger.analyzeUrl(url)
    return EnvLogger.output(outputPrefix or "envlogger_analysis")
end

-- ═════ Reset methods ═════

function EnvLogger.reset()
    Log.entries             = {}
    Log.count               = 0
    Log.startTime           = _os_clock()
    Log.urlsDiscovered      = {}
    Log.scriptsLoaded       = {}
    Log.errorsLogged        = {}
    Log.remotesCaptured     = {}
    Log.stringsDecrypted    = {}
    Log.vmOpcodes           = {}
    Log.vmIdentification    = {}
    Log.tableMutations      = {}
    Log.blockedOperations   = {}
    Log.hookDetections      = {}
    _vmLoopDetector.loopCounts   = {}
    _vmLoopDetector.funcCallSeqs = {}
end

function EnvLogger.hardReset()
    EnvLogger.reset()
    Log.idCounter  = 0
    Log.closureMap = {}
    Log.upvalueMap = {}
    for k in _pairs(_objectNames)   do _objectNames[k]   = nil end
    for k in _pairs(_objectIds)     do _objectIds[k]     = nil end
    for k in _pairs(_nameCounters)  do _nameCounters[k]  = nil end
    for k in _pairs(_wrappedFuncs)  do _wrappedFuncs[k]  = nil end
    for k in _pairs(_proxyToReal)   do _proxyToReal[k]   = nil end
    for k in _pairs(_realToProxy)   do _realToProxy[k]   = nil end
    for k in _pairs(_cycleTracker)  do _cycleTracker[k]  = nil end
    AutoSave.stop()
end

function EnvLogger.destroy()
    EnvLogger.hardReset()
    AutoSave.stop()
end

-- ═════ Webhook convenience ═════

function EnvLogger.setWebhook(url)
    Config.Webhook.Enabled = true
    Config.Webhook.Url = url
end

function EnvLogger.sendToWebhook()
    _task_spawn(Webhook.sendResults)
end

-- ═════ Expose internals ═════

EnvLogger.Config            = Config
EnvLogger.Log               = Log
EnvLogger.OpCodes           = OpCodes
EnvLogger.Serializer        = Serializer
EnvLogger.Reconstructor     = Reconstructor
EnvLogger.Proxy             = Proxy
EnvLogger.Hooker            = Hooker
EnvLogger.UrlEngine         = UrlEngine
EnvLogger.ClosureAnalyzer   = ClosureAnalyzer
EnvLogger.VMAnalyzer        = VMAnalyzer
EnvLogger.StringDeobf       = StringDeobf
EnvLogger.Webhook           = Webhook
EnvLogger.FileOutput        = FileOutput
EnvLogger.NamecallHook      = NamecallHook
EnvLogger.AutoSave          = AutoSave

return EnvLogger
