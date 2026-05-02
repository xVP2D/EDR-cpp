rule Test_Tree {
    strings:
        $ver    = "tree v2.2.1"
        $author = "Steve Baker, Thomas Moore"
    condition:
        $ver and $author
}
