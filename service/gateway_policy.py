"""Only the request shapes needed by this scanner may spend provider credentials."""
MODEL = 'claude-haiku-4-5-20251001'
MAX_BODY = 256 * 1024
MAX_RESPONSE = 2 * 1024 * 1024
MAX_TOKENS = 2048


def validate(data, role):
    if role not in {'scanner', 'analyst'}:
        raise ValueError('unknown workload role')
    if not isinstance(data, dict) or set(data) - {'model', 'max_tokens', 'system', 'messages', 'tools', 'stream'}:
        raise ValueError('unexpected request fields')
    if data.get('model') != MODEL or type(data.get('max_tokens')) is not int or not 1 <= data['max_tokens'] <= MAX_TOKENS:
        raise ValueError('model or output limit not allowed')
    if data.get('stream', False) is not False:
        raise ValueError('streaming is disabled')
    if not isinstance(data.get('system', ''), str) or len(data.get('system', '')) > 16000:
        raise ValueError('invalid system prompt')
    messages = data.get('messages')
    if not isinstance(messages, list) or not 1 <= len(messages) <= 32:
        raise ValueError('invalid message count')
    for message in messages:
        if not isinstance(message, dict) or set(message) != {'role', 'content'} or message['role'] not in {'user', 'assistant'}:
            raise ValueError('invalid message')
        content = message['content']
        if isinstance(content, str):
            continue
        if not isinstance(content, list) or not 1 <= len(content) <= 32:
            raise ValueError('invalid content')
        for block in content:
            if not isinstance(block, dict):
                raise ValueError('invalid block')
            kind = block.get('type')
            if kind == 'text':
                if set(block) - {'type', 'text', 'citations'} or not isinstance(block.get('text'), str) or block.get('citations') is not None:
                    raise ValueError('invalid text')
            elif kind == 'tool_use' and role == 'analyst':
                if set(block) != {'type', 'id', 'name', 'input'} or block['name'] != 'check_cve' or not isinstance(block['id'], str):
                    raise ValueError('tool not allowed')
                inputs = block['input']
                if not isinstance(inputs, dict) or set(inputs) != {'package', 'version'} or not all(isinstance(v, str) for v in inputs.values()):
                    raise ValueError('invalid tool arguments')
            elif kind == 'tool_result' and role == 'analyst':
                if set(block) - {'type', 'tool_use_id', 'content', 'is_error'} or not isinstance(block.get('content'), str) or not isinstance(block.get('tool_use_id'), str):
                    raise ValueError('invalid tool result')
                if 'is_error' in block and type(block['is_error']) is not bool:
                    raise ValueError('invalid tool error flag')
            else:
                raise ValueError('content type not allowed')
    tools = data.get('tools', [])
    if not isinstance(tools, list):
        raise ValueError('invalid tools list')
    if tools:
        if role != 'analyst' or not isinstance(tools, list) or len(tools) != 1:
            raise ValueError('tools not allowed for role')
        tool = tools[0]
        if not isinstance(tool, dict) or set(tool) - {'name', 'description', 'input_schema'} or tool.get('name') != 'check_cve':
            raise ValueError('tool not allowed')
        schema = tool.get('input_schema')
        expected = {'type': 'object', 'properties': {'package': {'type': 'string'}, 'version': {'type': 'string'}},
                    'required': ['package', 'version']}
        if schema != expected:
            raise ValueError('tool schema not allowed')
    return data
