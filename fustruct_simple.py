import sys
import clang.cindex
from clang.cindex import TypeKind
from clang.cindex import CursorKind
from clang.cindex import TokenKind

CONT = 1
STOP = 2

def visit_node(node):

    for c in node.get_children():
        self.walk_tree(c)


class TreeWalker(object):

    def __init__(self):
        self.handlers = {}
        self.depth = -1 
        self.file_h = ""
        self.stack = []

    def set_visitor(self, kind, handler):
        self.handlers[kind] = handler

    def walk_tree(self, node):

        self.log("%s : %s"  % (node.kind, node.spelling))
        if node.kind in self.handlers:
            self.depth += 1
            ret = self.handlers[node.kind](node, self)
            self.depth -= 1
            if ret != CONT:
                return

        self.depth += 1
        for c in node.get_children():
            self.walk_tree(c)
        self.depth -= 1

    def visit(self, node):
        self.walk_tree(node)

    def visit_children(self, node):
        for c in node.get_children():
            self.walk_tree(c)

    def log(self, msg):
        print self.depth*'\t' + ("%s" % msg)

    def write(self, data):
        self.file_h += self.depth*'\t' + data

    def write_raw(self, data):
        self.file_h += data

    def push(self, data):
        self.stack.append(data)

    def pop(self, data):
        self.stack.pop(data)

class Visitor(object):

    def __init__(self):
        pass

    def __call__(self, node, walker):
        ret = self.visit(node, walker)
        return ret

    def visit(node, walker):
        return CONT

class StructVisitor(Visitor):

    def __init__(self):
        # as the result we generate a header with all the structures and 
        # typedef 
        super(self.__class__, self).__init__()

    def visit(self, node, walker):
        tokens = map(lambda t: t.spelling, node.get_tokens())
        walker.write(' '.join(tokens) + ';')
        return STOP


class TypedefVisitor(Visitor):

    def __init__(self):
        super(self.__class__, self).__init__()

    def visit(self, node, walker):

        name = node.spelling
        _type = None


        if node.type.get_canonical().kind == TypeKind.RECORD:
            walker.write("typedef \n")
            for x in node.get_children():
                if not _type:
                    _type = x.spelling
                    # anonymous struct/union typedef
                    if len(_type) == 0:
                        x.force = True
                        walker.visit(x) 
                        walker.write(" %s;\n" % name)
                        return STOP
                else:
                    raise Exception("Typedef has more then one rec")

        elif node.type.get_canonical().kind == TypeKind.POINTER and \
                    self.__match_func_ptr(node.get_tokens()):

            params = []
            ret_type = None
            for x in node.get_children():
                # return type, if not primitive
                if x.kind == CursorKind.TYPE_REF:
                    ret_type = x.spelling
                else:
                    params.append("%s %s" % (x.type.spelling, x.spelling))

            if not ret_type:
                ret_type = self.__get_func_ptr_primitiv_ret(node.get_tokens())

            params = ', '.join(params)
            walker.write("typedef %s (*%s)(%s);\n" % (ret_type, name, params))
        else:
            # no ref, must be primitive
            print("AAAAA")
            print(node.type.get_canonical().kind)
            _type = None
            for x in node.get_children():
                _type = x.spelling

            if not _type:
                _type = node.type.get_canonical().spelling

            if node.type.get_canonical().kind == TypeKind.POINTER:
                _type += '*'

            code = "typedef %s %s" % (_type, name)
            align = node.type.get_align()

            if align != node.type.get_canonical().get_align():
                code += " __attribute__((aligned(%u)))" % align

            walker.write("%s;\n" % code)

        return STOP

class UnionVisitor(Visitor):

    def __init__(self):
        super(self.__class__, self).__init__()

    def decl_union_start(self, node, writer):

        if self.has_children:
            writer.write("union %s {\n" % node.spelling)
        else:
            writer.write("union %s" % node.spelling)

    def visit(self, node, walker):

        force = False
        if hasattr(node, 'force'):
            force = node.force

        if len(node.spelling) == 0 and not force:
            return STOP

        for c in node.get_children():
            self.has_children = True
            break

        if force:
            walker.write("union %s {\n" % node.spelling)
        else:
            self.decl_union_start(node, walker)

        walker.visit_children(node)

        if self.has_children:
            if len(node.spelling) > 0:
                walker.write("};\n");
            else:
                walker.write("}");
        else:
            walker.write_raw(";\n");

        return STOP

class EnumVisitor(Visitor):

    def __init__(self):
        super(self.__class__, self).__init__()

    def visit(self, node, walker):
        return CONT

clang.cindex.Config.set_library_path("/Library/Developer/CommandLineTools/usr/lib")

index = clang.cindex.Index.create()
#tu = index.parse(sys.argv[1])
tu = index.parse(sys.argv[1], ['-x', 'c++'])


struct_visitor = StructVisitor()
#typedef_visitor = TypedefVisitor()
#field_visitor = FieldVisitor()

#clang.cindex.Cursor_visit(tu.cursor, 
#        clang.cindex.Cursor_visit_callback(struct_visitor.visit), None)

walker = TreeWalker()
#walker.set_visitor(CursorKind.FIELD_DECL, field_visitor)
walker.set_visitor(CursorKind.STRUCT_DECL, struct_visitor)
#walker.set_visitor(CursorKind.TYPEDEF_DECL, typedef_visitor)
#walker.set_visitor(CursorKind.UNION_DECL, UnionVisitor())
#walker.set_visitor(CursorKind.ENUM_DECL, EnumVisitor())
walker.visit(tu.cursor)

print "------------ CODE ------------"
print walker.file_h

