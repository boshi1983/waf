local ChainList = {enable = false, head = nil, tail = nil};

function ChainList.setEnable(enable)
    ChainList.enable = enable
end

function ChainList.addNode(node)
    if ChainList.enable ~= true then
        return;
    end

    if nil == ChainList.head then
        ChainList.head = node;
    end

    if nil == ChainList.tail then
        ChainList.tail = node;
    else 
        ChainList.tail.next = node;
        ChainList.tail = node;
    end
end

function ChainList.run()
    if ChainList.enable ~= true then
        return;
    end
    local node = ChainList.head;
    while ( node ) do
        local rt = node.run();
        if rt then
           break;
        end
        node = node.next;
    end
end

function ChainList.newNode()
    local ChainNode = {next = nil;enable = false;};
    function ChainNode.setEnable(enable)
        ChainNode.enable = enable
    end
    return ChainNode;
end

return ChainList