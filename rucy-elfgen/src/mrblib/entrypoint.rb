module Rucy
  VAR_SIZE = {
    u8: 1,
    i8: 1,
    u16: 2,
    i16: 2,
    u32: 4,
    i32: 4,
    u64: 8,
    i64: 8
  }

  class << self
    def build_mode!
      @mode = :build
    end

    def object_create_mode!
      @mode = :object
    end

    def mode
      @mode
    end

    def build(&blk)
      if @mode == :object
        @dsl = Chunk.new
        blk.call(@dsl)
        nil
      end
    end

    def chunk
      @dsl
    end
  end

  class Chunk
    def funcname(v=nil)
      @funcname ||= v
    end

    def license(v=nil)
      @license ||= v
    end

    def section(v=nil)
      @section ||= v
    end

    def args(v=nil)
      if v
        @args = parse_args(v)
      else
        @args
      end
    end

    def function(&proc)
      @function ||= proc
    end

    def data(data=nil)
      @data ||= data
    end

    def parse_args(values)
      parsed = [nil]
      offset = 0

      values.each do |elm|
        if elm.is_a?(String)
          offset = 0
          parsed << {}
        else
          type, name = *elm
          parsed[-1][name] = offset
          offset += sizeof(type)
        end
      end
    end

    def sizeof(name)
      VAR_SIZE[name.to_sym] || raise("Invalid type name: #{name}")
    end
  end

  class Internal
    def self.register_dsl
      dsl = Rucy.chunk
      if ! dsl
        raise "DSL not registered"
      end

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
            scn.data "#{dsl.license}\x00"
          end

          e.section do |scn|
            scn.name dsl.section
            scn.symname(dsl.funcname || "rucy_bpf")
            scn.type SectionType::PROG

            if dsl.data
              scn.data dsl.data
            else
              scn.program(&dsl.function)
            end
          end

          e.section do |scn|
            scn.name ".symtab"
            scn.type SectionType::SYMTAB
          end
        end # header
      end # define
    end # method
  end
end
