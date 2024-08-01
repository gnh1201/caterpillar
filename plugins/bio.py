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

from Bio.Seq import Seq
from Bio.SeqUtils import gc_fraction

from base import Extension


def _analyze_sequence(sequence) -> dict[str, str]:
    """
    Analyze a given DNA sequence to provide various nucleotide transformations and translations.

    :param sequence: DNA sequence (string) to be analyzed.
    :return: Dictionary containing the following analyses of the sequence:
             - complement: DNA complement of the sequence.
             - complement_rna: RNA complement of the sequence.
             - reverse_complement: Reverse complement of the DNA sequence.
             - reverse_complement_rna: Reverse complement of the RNA sequence.
             - transcription: Transcription of the DNA sequence to RNA.
             - translation: Translation of the RNA sequence to an amino acid sequence.
             - back_transcribe: Back-transcription of the RNA sequence to DNA.
    """
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
    """
    Calculate the GC content of a given DNA sequence and return it as a float.

    :param sequence: DNA sequence (string) for which to calculate the GC content.
    :return: Dictionary containing the GC content as a float.
    """
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
        conn.send(b"Greeting! dispatch")

    def analyze_sequence(self, type, id, params, conn):
        """
        Analyze a DNA sequence provided in the params dictionary.

        :param type: Not used in this function.
        :param id: Not used in this function.
        :param params: Dictionary containing the DNA sequence with the key "sequence".
                       Example: {"sequence": "ATGCGTACGTAGCTAGCTAGCGTAGCTAGCTGACT"}
        :param conn: Not used in this function.
        :return: Dictionary containing various analyses of the DNA sequence:
                 - back_transcribe: Back-transcription of the RNA sequence to DNA.
                 - complement: DNA complement of the sequence.
                 - complement_rna: RNA complement of the sequence.
                 - reverse_complement: Reverse complement of the DNA sequence.
                 - reverse_complement_rna: Reverse complement of the RNA sequence.
                 - transcription: Transcription of the DNA sequence to RNA.
                 - translation: Translation of the RNA sequence to an amino acid sequence.
                 Example: {"back_transcribe": "ATGCGTACGTAGCTAGCTAGCGTAGCTAGCTGACT",
                           "complement": "TACGCATGCATCGATCGATCGCATCGATCGACTGA",
                           "complement_rna": "UACGCAUGCAUCGAUCGAUCGCAUCGAUCGACUGA",
                           "reverse_complement": "AGTCAGCTAGCTACGCTAGCTAGCTACGTACGCAT",
                           "reverse_complement_rna": "AGUCAGCUAGCUACGCUAGCUAGCUACGUACGCAU",
                           "transcription": "AUGCGUACGUAGCUAGCUAGCGUAGCUAGCUGACU",
                           "translation": "MRT*LASVAS*"}
        """
        result = _analyze_sequence(params["sequence"])
        return result

    def gc_content_calculation(self, type, id, params, conn):
        """
        Calculate the GC content for a given DNA sequence provided in the params dictionary.

        :param type: Not used in this function.
        :param id: Not used in this function.
        :param params: Dictionary containing the DNA sequence with the key "sequence".
                       Example: {"sequence": "ATGCGTACGTAGCTAGCTAGCGTAGCTAGCTGACT"}
        :param conn: Not used in this function.
        :return: Dictionary containing the GC content as a float.
                 Example: {"gc_content": 0.5142857142857142}
        """
        result = _gc_content_calculation(params["sequence"])
        return result
