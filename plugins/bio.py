#!/usr/bin/python3
#
# bio.py
# Biopython plugin for Caterpillar Proxy
#
# Euiseo Cha (Wonkwang University) <zeroday0619_dev@outlook.com>
# https://github.com/gnh1201/caterpillar
# Created at: 2024-07-02
# Updated at: 2024-07-02
#

import json
from Bio.Seq import Seq
from Bio.SeqUtils import gc_fraction

from server import Extension


def _analyze_sequence(sequence) -> dict[str, str]:
    sequence_object = Seq(sequence)
    return dict(
        complement=str(sequence_object.complement()),
        complement_rna=str(sequence_object.complement_rna()),
        reverse_complement=str(sequence_object.reverse_complement()),
        reverse_complement_rna=str(sequence_object.reverse_complement_rna()),
        transcription=str(sequence_object.transcribe()),
        translation=str(sequence_object.translate()),
        back_transcribe=str(sequence_object.back_transcribe()),
    )


def _gc_content_calculation(sequence) -> dict[str, str]:
    gc_content = gc_fraction(sequence)
    return dict(
        gc_content=gc_content,
    )


class PyBio(Extension):
    def __init__(self):
        self.type = "rpcmethod"
        self.method = "analyze_sequence_init"
        self.exported_methods = ["analyze_sequence", "gc_content_calculation"]

    def dispatch(self, type, id, params, conn):
        print("[*] Greeting! dispatch")
        conn.send(b'Greeting! dispatch')

    def analyze_sequence(self, type, id, params, conn):
        result = _analyze_sequence(params['sequence'])
        return result

    def gc_content_calculation(self, type, id, params, conn):
        result = _gc_content_calculation(params['sequence'])
        return result
