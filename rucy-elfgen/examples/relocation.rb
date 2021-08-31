include Rucy

code = "\xBF\x13\x00\x00\x00\x00\x00\x00a3\x04\x00\x00\x00\x00\x00\xB7\x04\x00\x00\x01\x00\x00\x00\x1FC\x00\x00\x00\x00\x00\x00U\x03\v\x00\x00\x00\x00\x00\x18\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xBF\x15\x00\x00\x00\x00\x00\x00aU\x00\x00\x00\x00\x00\x00\xBF\x16\x00\x00\x00\x00\x00\x00\xBF'\x00\x00\x00\x00\x00\x00\xBFA\x00\x00\x00\x00\x00\x00\xBFR\x00\x00\x00\x00\x00\x00\x85\x00\x00\x00\x06\x00\x00\x00\xBFa\x00\x00\x00\x00\x00\x00\xBFr\x00\x00\x00\x00\x00\x00\xB7\x03\x00\x00\x01\x00\x00\x00\xBF0\x00\x00\x00\x00\x00\x00\x95\x00\x00\x00\x00\x00\x00\x00"

ELFFile.define do |elf|
  elf.header do |e|
    e.type ET_REL
    e.machine EM_BPF

    e.section do |scn|
      scn.name ".strtab"
      scn.type SectionType::STRTAB
    end

    e.section do |scn|
      scn.name "license"
      scn.symname "__license"
      scn.type SectionType::LICENSE
      scn.data "GPL\x00"
    end

    e.section do |scn|
      scn.name "cgroup/dev"
      scn.symname "my_prog"
      scn.type SectionType::PROG

      scn.data code
    end

    e.section do |scn|
      scn.name ".rodata.str1.1"
      scn.symname ".L.str"
      scn.type SectionType::STRING
      scn.data "Access to character device detected. R/W: %d\x00"
    end

    e.section do |scn|
      scn.name ".relcgroup/dev"
      scn.type SectionType::REL
    end

    e.section do |scn|
      scn.name ".symtab"
      scn.type SectionType::SYMTAB
    end
  end
end
