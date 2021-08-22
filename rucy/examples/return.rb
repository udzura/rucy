Rucy.build do |prog|
  prog.license "GPL"
  prog.section "cgroup/dev"
  prog.args    [
    "struct bpf_cgroup_dev_ctx",
    [:u32, "access_type"], [:u32, "major"], [:u32, "minor"]
]

  prog.function do |ctx|
    return 0
  end
end
