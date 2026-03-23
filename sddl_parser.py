import re

ACE_TYPE_MAP = {
    'A': 'Access Allowed',
    'D': 'Access Denied',
    'OA': 'Object Access Allowed',
    'OD': 'Object Access Denied',
    'AU': 'System Audit',
    'AL': 'System Alarm',
}

PERMISSION_MAP = {
    'CC': 'Create Child',
    'DC': 'Delete Child',
    'LC': 'List Children',
    'SW': 'Self Write',
    'RP': 'Read Property',
    'WP': 'Write Property',
    'DT': 'Delete Tree',
    'LO': 'List Object',
    'CR': 'Control Access',
    'SD': 'Delete',
    'RC': 'Read Control',
    'WD': 'Write DACL',
    'WO': 'Write Owner',
    'FA': 'Full Control',
}

FLAG_MAP = {
    'CI': 'Container Inherit',
    'OI': 'Object Inherit',
    'NP': 'No Propagate',
    'IO': 'Inherited Only',
    'ID': 'Inherit only',
    'SA': 'Successful Access',
    'FA': 'Failed Access',
}

WELL_KNOWN_SIDS = {
    'S-1-5-18': 'Local System',
    'S-1-5-19': 'Local Service',
    'S-1-5-20': 'Network Service',
    'S-1-5-32-544': 'Administrators',
    'S-1-5-32-545': 'Users',
    'S-1-5-32-546': 'Guests',
    'S-1-5-32-548': 'Account Operators',
    'S-1-5-32-549': 'Server Operators',
    'S-1-5-32-550': 'Print Operators',
    'S-1-5-32-551': 'Backup Operators',
    'S-1-5-32-552': 'Replicators',
}

def explain_sid(sid):
    return WELL_KNOWN_SIDS.get(sid, "Пользователь или группа не определены")

def explain_operation_type(value):
    known_ops = {
        '%%14674': 'Создание или изменение объекта',
        '%%14675': 'Удаление объекта',
        '%%14676': 'Чтение объекта',
    }
    return known_ops.get(value, 'Неизвестная операция')

def explain_field_name(name):
    return {
        "SubjectUserName": "Имя пользователя",
        "SubjectUserSid": "SID пользователя",
        "ObjectDN": "Distinguished Name объекта",
        "ObjectClass": "Класс объекта",
        "OperationType": "Тип операции",
        "DSName": "Имя базы данных каталога",
        "SubjectDomainName": "Домен пользователя",
    }.get(name, name)

def parse_event_block(raw):
    result = {}
    for line in raw.strip().splitlines():
        if '\t' in line:
            key, val = line.split('\t', 1)
        elif '  ' in line:
            key, val = line.split('  ', 1)
        elif ':' in line:
            key, val = line.split(':', 1)
        else:
            continue
        result[key.strip()] = val.strip()
    return result

def parse_sddl(sddl):
    output = []

    match_owner = re.search(r'O:([^GDA]*)', sddl)
    match_group = re.search(r'G:([^DA]*)', sddl)
    match_dacl = re.search(r'D:(.*?)S:', sddl + 'S:')
    match_sacl = re.search(r'S:(.*)', sddl)

    if match_owner:
        output.append(f"Владелец: {match_owner.group(1)} ({explain_sid(match_owner.group(1))})")
    if match_group:
        output.append(f"Группа: {match_group.group(1)} ({explain_sid(match_group.group(1))})")

    if match_dacl:
        output.append("\nРазрешения (DACL):")
        output.extend(parse_aces(match_dacl.group(1)))

    if match_sacl:
        output.append("\nАудит (SACL):")
        output.extend(parse_aces(match_sacl.group(1)))

    return "\n".join(output)

def parse_aces(ace_block):
    aces = re.findall(r'\(([^)]+)\)', ace_block)
    results = []
    for ace in aces:
        parts = ace.split(';')
        ace_type = ACE_TYPE_MAP.get(parts[0], parts[0])
        flags = ', '.join([FLAG_MAP.get(f, f) for f in re.findall(r'.{2}', parts[1]) if f])
        rights = ', '.join([PERMISSION_MAP.get(r, r) for r in re.findall(r'.{2}', parts[2]) if r])
        object_guid = parts[3] or "-"
        inherited_object_guid = parts[4] or "-"
        sid = parts[5]
        sid_desc = explain_sid(sid)
        results.append(
            f"  ▫ Тип: {ace_type}\n"
            f"    Флаги: {flags or '-'}\n"
            f"    Права: {rights or '-'}\n"
            f"    Object GUID: {object_guid}\n"
            f"    Inherited GUID: {inherited_object_guid}\n"
            f"    SID: {sid} ({sid_desc})"
        )
    return results
