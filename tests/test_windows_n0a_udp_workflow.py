"""Short direct UDP adapter gates; no guest runtime or artifact publication."""
import ast
import hashlib
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/'.github/workflows/windows-n0a-udp-gates.yml'
BRANCH='refs/heads/dot/windows-isolation-proof'
MARKER='[n0a-udp-gates]'
NAMES=('test_windows_n0a_udp_actor.py', 'test_windows_client_n0a_udp.py', 'test_windows_n0a_udp_gate.py', 'test_windows_client_n0a_udp_packet.py', 'test_windows_n0a_udp_workflow.py', 'test_windows_client_n0a_udp_guest.py', 'test_windows_client_n0a_udp_flow.py', 'test_windows_client_n0a_udp_host.py', 'test_windows_client_n0a_udp_capture_adapter.py', 'test_windows_udp_guest_transport.py', 'test_windows_udp_payload.py', 'test_windows_udp_flow_composed.py', 'test_windows_n0a_actor.py', 'test_windows_client_n0a_control.py', 'test_windows_n0a_workflow.py', 'test_windows_client_n0a_adapter.py', 'test_windows_client_n0a_host.py', 'test_windows_client_n0a_flow.py', 'test_windows_client_n0a_capture_adapter.py', 'test_windows_client_n0a_packet.py', 'test_windows_n0a_guest.py', 'test_windows_client_direct_stage0.py', 'test_windows_client_direct_guest.py', 'test_windows_client_direct_actor_projection.py', 'test_windows_client_direct_workflow.py')


# Exact reviewed parent-activation inverse: changed line spans are hash-bound;
# untouched lines must still reproduce the preactivation workflow byte-for-byte.
PARENT_ACTIVATION_INVERSE = ((32, 43, '4466fc0f0dc057417a939c627387d99440a9f98f84a8da99a4ab3807697ddab3', ''),
 (49,
  50,
  'ffe1b2676007a71179059783b9d07742dbe54d4ee607a06d0e72c282d2fd512e',
  "    if: ${{ true && github.ref == 'refs/heads/dot/windows-isolation-proof' && github.event_name == 'push' "
  "&& (contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') || "
  "contains(github.event.head_commit.message, '[identity-direct-stage0-gates]') || "
  "contains(github.event.head_commit.message, '[n0a-connect-runtime]') || "
  "contains(github.event.head_commit.message, '[n0a-capture-runtime]') || "
  "contains(github.event.head_commit.message, '[n0a-udp-runtime]')) }}\n"),
 (97,
  98,
  '6bdc133567fc4719fa59cce5241736b99bb4ec6f3a6f4b534f7cffdd8cea3202',
  "        if: ${{ (contains(github.event.head_commit.message, '[n0a-connect-runtime]') || "
  "contains(github.event.head_commit.message, '[n0a-capture-runtime]')) }}\n"),
 (110,
  111,
  '47bd0fc843bbfd1bf64e5065edda7198981c406b733aa0503517b65bd155198b',
  "        if: ${{ true && (contains(github.event.head_commit.message, '[n0a-connect-runtime]') || "
  "contains(github.event.head_commit.message, '[n0a-capture-runtime]')) }}\n"),
 (118, 155, '7ac618300d3498323d595812ad3be6cd4d5160141e6094a4bd583cfbd6a42cdf', ''),
 (156,
  157,
  '318be73f6add1cc4da31f15af426ad713986311b48536ef90009e3a9f1668b49',
  "        if: ${{ contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') }}\n"),
 (170,
  171,
  '318be73f6add1cc4da31f15af426ad713986311b48536ef90009e3a9f1668b49',
  "        if: ${{ contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') }}\n"),
 (181,
  182,
  'ef7eed98a2c9b68fbb8a0fdb1b4104d03ea4f41a996666b8b926b808072fb533',
  "        if: ${{ contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') }}\n"),
 (199,
  200,
  'ffe1b2676007a71179059783b9d07742dbe54d4ee607a06d0e72c282d2fd512e',
  "    if: ${{ true && github.ref == 'refs/heads/dot/windows-isolation-proof' && github.event_name == 'push' "
  "&& (contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') || "
  "contains(github.event.head_commit.message, '[identity-direct-stage0-gates]') || "
  "contains(github.event.head_commit.message, '[n0a-connect-runtime]') || "
  "contains(github.event.head_commit.message, '[n0a-capture-runtime]') || "
  "contains(github.event.head_commit.message, '[n0a-udp-runtime]')) }}\n"),
 (217,
  218,
  '318be73f6add1cc4da31f15af426ad713986311b48536ef90009e3a9f1668b49',
  "        if: ${{ contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') }}\n"),
 (221, 226, 'bec6f2bd63f65ca64752345346bd7e219efc6eed75f1fb678f07161679220647', ''),
 (227,
  228,
  'b48a6facefd8d06d5cec36a0bd039a5e6733fdca87a523cb56b291eefea3fa66',
  "    if: ${{ true && github.ref == 'refs/heads/dot/windows-isolation-proof' && github.event_name == 'push' "
  "&& ((contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-runtime]')) || "
  "(!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-runtime]')) || "
  "(!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-runtime]')) || "
  "(!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "contains(github.event.head_commit.message, '[n0a-udp-runtime]'))) }}\n"),
 (355,
  361,
  '7556a4b5ae87705bb4af5129dad764df57287d52e68aef61d0db27526b8e3f0a',
  "        if: ${{ contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') }}\n"),
 (365,
  366,
  '6bdc133567fc4719fa59cce5241736b99bb4ec6f3a6f4b534f7cffdd8cea3202',
  "        if: ${{ (contains(github.event.head_commit.message, '[n0a-connect-runtime]') || "
  "contains(github.event.head_commit.message, '[n0a-capture-runtime]')) }}\n"),
 (462, 463, 'e0a8bbf574321ca12575ade654e2817848c83751cf85ff15926fd0e0844a5d08', ''),
 (466,
  467,
  '4b9a3f3990994e1ff127013bd957bd65c4771c385ce1ff91966f0879b49ee597',
  "          N0A_REQUESTED: ${{ (contains(github.event.head_commit.message, '[n0a-connect-runtime]') || "
  "contains(github.event.head_commit.message, '[n0a-capture-runtime]')) }}\n"),
 (480, 486, '754bd9f0b2ce5c965deec33821ec883a4290f4031b95638432c1f921a1e4d548', ''),
 (487,
  488,
  '8d70e77684860840613a0739ffae9a80df6f3eb230b1c9812cb54c367e7c173b',
  '          if [ "$CAPTURE_REQUESTED" = "true" ] || [ "$UDP_REQUESTED" = "true" ]; then\n'),
 (520,
  521,
  '3dbf1dc2f82c82d46aed9342be6abe4caeddc6dd20843ace53abc55877a4b0ea',
  "        if: ${{ always() && (contains(github.event.head_commit.message, '[n0a-connect-runtime]') || "
  "contains(github.event.head_commit.message, '[n0a-capture-runtime]')) }}\n"),
 (536,
  537,
  '04bd3ce1b6a79b9159f3bb71a3cbcfe2655e22528aa0e98ad7e7d5871e164b14',
  "        if: ${{ always() && contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') }}\n"),
 (541, 549, '85cd0582f8bf9a1c9b418de278655e1ce6aa9cfa399d15eeac7ffca62ad884f6', ''))


# Exact UDP6-only delta reversed before the prior parent activation inverse.
UDP6_ACTIVATION_INVERSE = ((43, 51, 'bdc8592c9da38a16c0d8f682aec31891af0dae31c4b3e5cc30ad164a4101528a', ''),
 (57,
  58,
  '7de3a682faa52943d721d427bd3dab7046ca7b26a1f1e5b5d8cefc90ca1161ec',
  "    if: ${{ true && github.ref == 'refs/heads/dot/windows-isolation-proof' && github.event_name == 'push' "
  "&& (contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') || "
  "contains(github.event.head_commit.message, '[identity-direct-stage0-gates]') || "
  "contains(github.event.head_commit.message, '[n0a-connect-runtime]') || "
  "contains(github.event.head_commit.message, '[n0a-capture-runtime]') || "
  "contains(github.event.head_commit.message, '[n0a-udp-runtime]') || "
  "contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) }}\n"),
 (105,
  106,
  'abad65e75f366fa586af2c2ecaa5a765a185c2163914bbf43a6781e4316b6592',
  "        if: ${{ (contains(github.event.head_commit.message, '[n0a-connect-runtime]') || "
  "contains(github.event.head_commit.message, '[n0a-capture-runtime]')) && "
  "!contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') }}\n"),
 (118,
  119,
  'facc6d2c9b9c06da5b7c7c6971cf8bf0713766db2a5fb16be49c77bd58f4f964',
  "        if: ${{ true && (contains(github.event.head_commit.message, '[n0a-connect-runtime]') || "
  "contains(github.event.head_commit.message, '[n0a-capture-runtime]')) && "
  "!contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') }}\n"),
 (126, 162, 'b41ea54bdbf1c8d21eece98365306645b0a61129a645917cedf0d4ec2dc6ae4b', ''),
 (163,
  164,
  'de10d68e7798856626d49b08e95a7f6becda2c132249a23439056d23df65797d',
  "        if: ${{ !contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') }}\n"),
 (182,
  183,
  'de10d68e7798856626d49b08e95a7f6becda2c132249a23439056d23df65797d',
  "        if: ${{ !contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') }}\n"),
 (191,
  192,
  'de10d68e7798856626d49b08e95a7f6becda2c132249a23439056d23df65797d',
  "        if: ${{ !contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') }}\n"),
 (200,
  201,
  '4eb035035eed9bed125de7f61b3f5bfef628d3ad190449811e0665701f8de43c',
  "        if: ${{ contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') }}\n"),
 (214,
  215,
  '4eb035035eed9bed125de7f61b3f5bfef628d3ad190449811e0665701f8de43c',
  "        if: ${{ contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') }}\n"),
 (225,
  226,
  '3e8aa34e6a4f6a9bb253e3f7a07026304b0b4ad413fe8397cd15c07b2c3231a6',
  "        if: ${{ ((contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) || "
  "(!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]'))) }}\n"),
 (243,
  244,
  '7de3a682faa52943d721d427bd3dab7046ca7b26a1f1e5b5d8cefc90ca1161ec',
  "    if: ${{ true && github.ref == 'refs/heads/dot/windows-isolation-proof' && github.event_name == 'push' "
  "&& (contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') || "
  "contains(github.event.head_commit.message, '[identity-direct-stage0-gates]') || "
  "contains(github.event.head_commit.message, '[n0a-connect-runtime]') || "
  "contains(github.event.head_commit.message, '[n0a-capture-runtime]') || "
  "contains(github.event.head_commit.message, '[n0a-udp-runtime]') || "
  "contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) }}\n"),
 (261,
  262,
  '4eb035035eed9bed125de7f61b3f5bfef628d3ad190449811e0665701f8de43c',
  "        if: ${{ contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') }}\n"),
 (266,
  267,
  'de10d68e7798856626d49b08e95a7f6becda2c132249a23439056d23df65797d',
  "        if: ${{ !contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') }}\n"),
 (270, 275, '2a31f7f14728f9bd957e7b2411ec6571b5a946d490feec3fb742f4030368ec49', ''),
 (276,
  277,
  'f9427449d921c1854419bbcf029d2f07f857c637ede78748acb0608d526d71d4',
  "    if: ${{ true && github.ref == 'refs/heads/dot/windows-isolation-proof' && github.event_name == 'push' "
  "&& ((contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) || "
  "(!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) || "
  "(!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) || "
  "(!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) || "
  "(!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]'))) }}\n"),
 (399, 404, '5fa6591916f7cdc5942ebd44e58636ba6fbfc4a0fce0643472efac7f7411f982', ''),
 (409,
  410,
  'de10d68e7798856626d49b08e95a7f6becda2c132249a23439056d23df65797d',
  "        if: ${{ !contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') }}\n"),
 (414,
  415,
  '3e8aa34e6a4f6a9bb253e3f7a07026304b0b4ad413fe8397cd15c07b2c3231a6',
  "        if: ${{ ((contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) || "
  "(!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]'))) }}\n"),
 (419,
  420,
  'abad65e75f366fa586af2c2ecaa5a765a185c2163914bbf43a6781e4316b6592',
  "        if: ${{ (contains(github.event.head_commit.message, '[n0a-connect-runtime]') || "
  "contains(github.event.head_commit.message, '[n0a-capture-runtime]')) && "
  "!contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') }}\n"),
 (516, 517, '10dc364a0cf00c62207db167bc2d5efeb15314cc9498c3d3d2a79b011d5d2003', ''),
 (541, 548, '4cda804e2b4af496b7268a5c61d920b51c7d0be46a4b9df1847f998aeb3350b5', ''),
 (549,
  550,
  '4c78ecf0ea7c93f674cd449a8bb53791d3e8e7346d93af24f91695b975284d6d',
  '          if [ "$CAPTURE_REQUESTED" = "true" ] || [ "$UDP_REQUESTED" = "true" ] || [ '
  '"$PARENT_UDP_REQUESTED" = "true" ]; then\n'),
 (582,
  583,
  '321f62dda11e871a0908a4ce6db9404cd788dca29fee8cd102ac978c5aca0ead',
  "        if: ${{ always() && (contains(github.event.head_commit.message, '[n0a-connect-runtime]') || "
  "contains(github.event.head_commit.message, '[n0a-capture-runtime]')) && "
  "!contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') }}\n"),
 (590,
  591,
  'f4dae7dfa7b90090bdb2eafc2b7aa6fb8264df4134cec272ae05e6526cfbe57e',
  "        if: ${{ always() && contains(github.event.head_commit.message, '[n0a-capture-runtime]') }}\n"),
 (598,
  599,
  '8e75c7c2d21c4dd28e7e344f17054ccca6a98b46f4f44f7434e9f8a51b7ca1b7',
  "        if: ${{ always() && contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-connect-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') }}\n"),
 (606,
  607,
  '3f3e59f42ead45d26fbd44572042f5808793477025c8a46dde6978f862bca190',
  '        if: ${{ always() && !contains(github.event.head_commit.message, '
  "'[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, "
  "'[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && "
  "!contains(github.event.head_commit.message, '[n0a-udp-runtime]') && "
  "contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') }}\n"),
 (627, 635, 'd3244c28c5e59271035066c89ec5dbe2a3e7a94a087e3a312d4e23ffae064dfc', ''))

STAGE0B_ACTIVATION_INVERSE = ((51, 61, '26a017a713f4fc0018a1768b209bee4d4d4f1b9b98a4b88b4124bcd146e26818', ''), (67, 68, 'ac161abb4ac67f0d1d4f88aac9a8bd84ac8f5275f277cdec2ae05182fa0747eb', "    if: ${{ true && github.ref == 'refs/heads/dot/windows-isolation-proof' && github.event_name == 'push' && (contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') || contains(github.event.head_commit.message, '[identity-direct-stage0-gates]') || contains(github.event.head_commit.message, '[n0a-connect-runtime]') || contains(github.event.head_commit.message, '[n0a-capture-runtime]') || contains(github.event.head_commit.message, '[n0a-udp-runtime]') || contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') || contains(github.event.head_commit.message, '[n0a-udp6-runtime]')) }}\n"), (115, 116, 'd73837309aee9851c8869c042c5d0110030dc94077b0c74cae2167ce9bc81097', "        if: ${{ ((contains(github.event.head_commit.message, '[n0a-connect-runtime]') || contains(github.event.head_commit.message, '[n0a-capture-runtime]')) && !contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) && !contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (128, 129, '56912be8f6cd80dedee01b1f56f3b73d4a860946d60a19401cd73670cf5f2960', "        if: ${{ (true && (contains(github.event.head_commit.message, '[n0a-connect-runtime]') || contains(github.event.head_commit.message, '[n0a-capture-runtime]')) && !contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) && !contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (137, 138, '9ddde4749d0fd5286ddf3a3c46908299a296612a9933dcce934cd5dfa64c9f89', "        if: ${{ !contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') && contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (155, 156, '9ddde4749d0fd5286ddf3a3c46908299a296612a9933dcce934cd5dfa64c9f89', "        if: ${{ !contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') && contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (164, 165, '9ddde4749d0fd5286ddf3a3c46908299a296612a9933dcce934cd5dfa64c9f89', "        if: ${{ !contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') && contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (173, 174, '45fe359cd3e7ec4df73875ee61051ff380d688677fae93f8db1ced801e699b31', "        if: ${{ (!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-runtime]') && contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) && !contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (192, 193, '45fe359cd3e7ec4df73875ee61051ff380d688677fae93f8db1ced801e699b31', "        if: ${{ (!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-runtime]') && contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) && !contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (201, 202, '45fe359cd3e7ec4df73875ee61051ff380d688677fae93f8db1ced801e699b31', "        if: ${{ (!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-runtime]') && contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) && !contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (210, 211, 'b02bd0f74e8494757dbddbf0da6a6ab53e2ce244c485288a09e107e3f72712c6', "        if: ${{ (contains(github.event.head_commit.message, '[n0a-udp-runtime]') && !contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) && !contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (224, 225, 'b02bd0f74e8494757dbddbf0da6a6ab53e2ce244c485288a09e107e3f72712c6', "        if: ${{ (contains(github.event.head_commit.message, '[n0a-udp-runtime]') && !contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) && !contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (235, 236, 'b17b03b3eb5027bc8d7fbea48a0ba951e1d87683c4164a24c4ffdbccf903ff01', "        if: ${{ (((contains(github.event.head_commit.message, '[n0a-udp-runtime]') && !contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) || (!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-runtime]') && contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')))) && !contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (243, 269, '7e849fe3006433b93bcc19f89ea726b5d51717dbf13eaad9fac9d5109b7bf701', ''), (279, 280, 'ac161abb4ac67f0d1d4f88aac9a8bd84ac8f5275f277cdec2ae05182fa0747eb', "    if: ${{ true && github.ref == 'refs/heads/dot/windows-isolation-proof' && github.event_name == 'push' && (contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') || contains(github.event.head_commit.message, '[identity-direct-stage0-gates]') || contains(github.event.head_commit.message, '[n0a-connect-runtime]') || contains(github.event.head_commit.message, '[n0a-capture-runtime]') || contains(github.event.head_commit.message, '[n0a-udp-runtime]') || contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') || contains(github.event.head_commit.message, '[n0a-udp6-runtime]')) }}\n"), (297, 298, 'b02bd0f74e8494757dbddbf0da6a6ab53e2ce244c485288a09e107e3f72712c6', "        if: ${{ (contains(github.event.head_commit.message, '[n0a-udp-runtime]') && !contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) && !contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (302, 303, '45fe359cd3e7ec4df73875ee61051ff380d688677fae93f8db1ced801e699b31', "        if: ${{ (!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-runtime]') && contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) && !contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (307, 308, '9ddde4749d0fd5286ddf3a3c46908299a296612a9933dcce934cd5dfa64c9f89', "        if: ${{ !contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') && contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (311, 316, 'a794478672a3231e6830e6947d41f3bd9fc58bc3c5ba43e76f4d5f7a7c75508f', ''), (317, 318, '3495c0e8e263ea6d6425078d11fd24c1317b86b87bacd29c2a76a15176c79b4d', "    if: ${{ true && github.ref == 'refs/heads/dot/windows-isolation-proof' && github.event_name == 'push' && ((contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp6-runtime]')) || (!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp6-runtime]')) || (!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp6-runtime]')) || (!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && contains(github.event.head_commit.message, '[n0a-udp-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp6-runtime]')) || (!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-runtime]') && contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp6-runtime]')) || (!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') && contains(github.event.head_commit.message, '[n0a-udp6-runtime]'))) }}\n"), (440, 441, '9ddde4749d0fd5286ddf3a3c46908299a296612a9933dcce934cd5dfa64c9f89', "        if: ${{ !contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') && contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (450, 451, '45fe359cd3e7ec4df73875ee61051ff380d688677fae93f8db1ced801e699b31', "        if: ${{ (!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-runtime]') && contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) && !contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (455, 456, 'b17b03b3eb5027bc8d7fbea48a0ba951e1d87683c4164a24c4ffdbccf903ff01', "        if: ${{ (((contains(github.event.head_commit.message, '[n0a-udp-runtime]') && !contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) || (!contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-runtime]') && contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')))) && !contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (460, 461, 'd73837309aee9851c8869c042c5d0110030dc94077b0c74cae2167ce9bc81097', "        if: ${{ ((contains(github.event.head_commit.message, '[n0a-connect-runtime]') || contains(github.event.head_commit.message, '[n0a-capture-runtime]')) && !contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) && !contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (557, 558, '2beb3e34dcf14612c17b68aa1793f628ea4af382a8e96d285b4469b6b84867a1', ''), (590, 601, 'ed139d66b31fd2f1262b21fcfe74220c6b9f34f504a25789ffeb4847175afd00', ''), (602, 603, '251af1c7ccf832be0a210a82a3d2a3d4f586438e29f4fa43810602e20de1934a', '          if [ "$CAPTURE_REQUESTED" = "true" ] || [ "$UDP_REQUESTED" = "true" ] || [ "$PARENT_UDP_REQUESTED" = "true" ] || [ "$UDP6_REQUESTED" = "true" ]; then\n'), (635, 636, 'e0bd40842426ddd09d11f032f763bfbaf4033d758b5e6caf652321a489162e37', "        if: ${{ (always() && (contains(github.event.head_commit.message, '[n0a-connect-runtime]') || contains(github.event.head_commit.message, '[n0a-capture-runtime]')) && !contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) && !contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (643, 644, 'b8496e3a540d083e6ffbf927355a3a6138ddbe37509a0dd0a59f139b15212733', "        if: ${{ (always() && contains(github.event.head_commit.message, '[n0a-capture-runtime]')) && !contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (651, 652, '4e171ab73386ec1b0183bc1f6b6a49002260122cdc87e3f662c1beb92bb9db25', "        if: ${{ (always() && contains(github.event.head_commit.message, '[n0a-udp-runtime]') && !contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) && !contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (659, 660, '1d0b7d4af7cc6bee09efa2722affba5d4e34ffe2c650d63d0e74d25eedbf9ff4', "        if: ${{ (always() && !contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-runtime]') && contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]')) && !contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (681, 682, '98d099ddbd835fbe2049c7ee2a40e7a5a94d03381555f36956c27f22efa97030', "        if: ${{ always() && !contains(github.event.head_commit.message, '[identity-direct-stage0-runtime]') && !contains(github.event.head_commit.message, '[n0a-connect-runtime]') && !contains(github.event.head_commit.message, '[n0a-capture-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-runtime]') && !contains(github.event.head_commit.message, '[n0a-udp-parent-runtime]') && contains(github.event.head_commit.message, '[n0a-udp6-runtime]') }}\n"), (688, 696, '2ab0c0939d886dacad5de5e667c084674b181f80b946ee6c276babee01ea0c64', ''))

def undo_stage0b_activation(text):
    lines=text.splitlines(keepends=True)
    for start,end,digest,prior in reversed(STAGE0B_ACTIVATION_INVERSE):
        if hashlib.sha256("".join(lines[start:end]).encode()).hexdigest()!=digest:raise AssertionError('Stage0b activation delta changed')
        lines[start:end]=prior.splitlines(keepends=True)
    restored="".join(lines)
    if hashlib.sha256(restored.encode()).hexdigest()!='9e618b5f1c8cd8ccb39d1eb654432ce98d4c4fdaca6c0c4be4a52629e94c569a':raise AssertionError('Unrelated pre-Stage0b workflow change')
    return restored

def undo_udp6_activation(text):
    text=undo_stage0b_activation(text)
    # Peer-context source changes update the pin, not runtime wiring.
    current="bba6b0049060deeb67ea00a7d28dc4186652f9bee5f3375cb7e089a85126d7fc"
    if text.count(current)!=1:raise AssertionError("UDP6 diagnostic source pin")
    text=text.replace(current,"2b06fa49217e0994abcf94a265ee7eff998c8766b0a37fe312754bbb1fb0e6f6")
    lines=text.splitlines(keepends=True)
    for start,end,digest,prior in reversed(UDP6_ACTIVATION_INVERSE):
        if hashlib.sha256("".join(lines[start:end]).encode()).hexdigest()!=digest:raise AssertionError("UDP6 activation delta changed")
        lines[start:end]=prior.splitlines(keepends=True)
    restored="".join(lines)
    if hashlib.sha256(restored.encode()).hexdigest()!='657987cc2496cd8088bdebb35aaad427acc7dfeaf7d7d6755d40f505be694b5f':raise AssertionError("Unrelated pre-UDP6 workflow change")
    return restored

def undo_parent_activation(text):
    text=undo_udp6_activation(text)
    lines=text.splitlines(keepends=True)
    for start,end,digest,prior in reversed(PARENT_ACTIVATION_INVERSE):
        if hashlib.sha256("".join(lines[start:end]).encode()).hexdigest()!=digest:
            raise AssertionError("Parent activation delta changed")
        lines[start:end]=prior.splitlines(keepends=True)
    restored="".join(lines)
    if hashlib.sha256(restored.encode()).hexdigest()!='8676ff93f3b27b0bcaab6bacefa331b309feb9b1d175c7f618b0346f08a46e2c':
        raise AssertionError("Unrelated runtime workflow change")
    return restored


def condition(expression,message,branch=BRANCH,event='push'):
    value=re.sub(r"contains\(github.event.head_commit.message, '([^']+)'\)",lambda m:str(m.group(1) in message),expression)
    value=value.replace('github.ref',repr(branch)).replace('github.event_name',repr(event))
    value=re.sub(r'\btrue\b','True',value);value=re.sub(r'\bfalse\b','False',value)
    value=value.replace('&&',' and ').replace('||',' or ').replace('!',' not ')
    tree=ast.parse(value.strip(),mode='eval')
    allowed=(ast.Expression,ast.BoolOp,ast.UnaryOp,ast.Compare,ast.Constant,ast.And,ast.Or,ast.Not,ast.Eq,ast.Load)
    if any(not isinstance(node,allowed) for node in ast.walk(tree)):raise ValueError('condition')
    return eval(compile(tree,'<actual-job-condition>','eval'),{'__builtins__':{}},{})


class UdpWorkflowTests(unittest.TestCase):
    def test_real_yaml_structure_and_runtime_baseline_delta(self):
        import yaml
        # BaseLoader deliberately preserves the YAML key "on" as a string,
        # rather than SafeLoader's YAML 1.1 boolean resolver.
        direct=ROOT/'.github/workflows/windows-identity-direct-stage0.yml'
        texts=[PATH.read_text(encoding='utf-8'),direct.read_text(encoding='utf-8')]
        for text in texts:
            doc=yaml.load(text,Loader=yaml.BaseLoader)
            self.assertEqual(doc['permissions'],{'contents':'read'})
            self.assertEqual(doc['on']['push']['branches'],['dot/windows-isolation-proof'])
            self.assertIn('tests/test_windows_udp_flow_composed.py',doc['on']['push']['paths'])
            self.assertEqual(text.count('pip install --disable-pip-version-check "PyYAML==6.0.3"'),2 if text==texts[0] else 8)
            self.assertIn('          python -m pip install --disable-pip-version-check "PyYAML==6.0.3"\n          if ($LASTEXITCODE -ne 0) { throw "yaml_test_dependency_install_failed" }\n',text)
            for job in doc['jobs'].values():
                self.assertIsInstance(job['steps'],list)
                self.assertIsInstance(job['if'],str)
        short=yaml.load(texts[0],Loader=yaml.BaseLoader)
        self.assertEqual(set(short['on']),{'push'})
        self.assertEqual(set(short['jobs']),{'pure','native-mechanism'})
        self.assertEqual(short['jobs']['pure']['timeout-minutes'],'5')
        self.assertEqual(short['jobs']['native-mechanism']['timeout-minutes'],'8')
        runtime=yaml.load(texts[1],Loader=yaml.BaseLoader)
        self.assertEqual(set(runtime['on']),{'push','workflow_dispatch'})
        self.assertEqual(runtime['on']['workflow_dispatch'],'')
        self.assertEqual(set(runtime['jobs']),{'compile','host-unit','native'})
        self.assertEqual(runtime['jobs']['native']['timeout-minutes'],'120')
        self.assertEqual(runtime['jobs']['native']['permissions'],{'contents':'read','actions':'read'})
        self.assertEqual(runtime['jobs']['native']['needs'],['compile','host-unit'])
        # Reversing only intended path/suite/test-dependency edits must recover
        # exact published 9a22193e bytes, including every native job setting.
        old=undo_parent_activation(texts[1]).replace("      - 'tests/test_windows_udp_flow_composed.py'\n",'')
        old=old.replace("'test_windows_udp_flow_composed.py', ",'')
        old=old.replace('          python -m pip install --disable-pip-version-check "PyYAML==6.0.3"\n          if ($LASTEXITCODE -ne 0) { throw "yaml_test_dependency_install_failed" }\n','')
        old=old.replace('          python3 -m pip install --disable-pip-version-check "PyYAML==6.0.3"\n','')
        self.assertEqual(hashlib.sha256(old.encode()).hexdigest(),'6b55e831d68c8617761703aef9c7a359b5f8a82aac6443a4e670af4f2ba68ec6')

    def test_parent_inverse_rejects_changed_delta_and_unrelated_resources(self):
        current=(PATH.parent/'windows-identity-direct-stage0.yml').read_text()
        self.assertTrue(undo_parent_activation(current))
        for changed in (current.replace('timeout-minutes: 120','timeout-minutes: 121',1),
                        current.replace('Build pinned production descendant parent and child','Changed parent build',1)):
            self.assertNotEqual(changed,current)
            with self.assertRaises(AssertionError):undo_parent_activation(changed)

    def setUp(self):self.text=PATH.read_text()

    def test_exact_marker_branch_event(self):
        self.assertEqual(re.findall(r'^  ([a-z][a-z-]+):$',self.text.split('jobs:',1)[1],re.M),['pure','native-mechanism'])
        expressions=re.findall(r'^    if: \$\{\{ (.+) \}\}$',self.text,re.M)
        self.assertEqual(len(expressions),2)
        for expression in expressions:
            self.assertTrue(condition(expression,MARKER))
            for msg in ('unrelated','[dns-request3-gates]','[n0a-connect-gates]','[n0a-capture-gates]','[n0a-connect-runtime]','[n0a-capture-runtime]','[identity-direct-stage0-runtime]','[identity-serviced-stage0-runtime]'):
                self.assertFalse(condition(expression,msg))
            for branch in ('refs/heads/main',BRANCH+'-other'):
                self.assertFalse(condition(expression,MARKER,branch=branch))
            for event in ('workflow_dispatch','pull_request','schedule'):
                self.assertFalse(condition(expression,MARKER,event=event))

    def test_udp_marker_cannot_start_existing_work(self):
        for name in ('windows-identity-direct-stage0.yml','windows-identity-serviced-stage0.yml','windows-n0a-connect-gates.yml','windows-n0a-capture-gates.yml','windows-dns-request3-gates.yml'):
            expressions=re.findall(r'^    if: \$\{\{ (.+) \}\}$',(ROOT/'.github/workflows'/name).read_text(),re.M)
            self.assertTrue(expressions)
            for expression in expressions:self.assertFalse(condition(expression,MARKER),name)

    def test_fixed_resources_and_no_upload_or_runtime(self):
        self.assertIn('runs-on: ubuntu-24.04',self.text);self.assertIn('runs-on: windows-2025',self.text)
        self.assertEqual(re.findall(r'^    timeout-minutes: (\d+)$',self.text,re.M),['5','8'])
        self.assertEqual(self.text.count('persist-credentials: false'),2)
        for x in ('contents: read','cancel-in-progress: false','timeout-minutes: 2'):self.assertIn(x,self.text)
        for x in ('workflow_dispatch:','schedule:','pull_request:','upload-artifact','download-artifact','continue-on-error','qemu-system','sudo ','--approved-disposable-vm','--n0a-capture-runner'):
            self.assertNotIn(x,self.text)

    def test_required_tests_before_actual_mechanics(self):
        for name in NAMES:self.assertEqual(self.text.count("'"+name+"'"),2)
        self.assertEqual(self.text.count('p.countTestCases()>0'),2)
        self.assertEqual(self.text.count('bool(result.skipped)'),2)
        self.assertLess(self.text.index('Required UDP contracts before actual mechanics'),self.text.index('Owned loopback mechanics'))
        self.assertNotIn('test_windows_dns_request3.py',self.text)

    def test_adapter_gates_and_separate_runtime_entrypoint(self):
        for name in ('test-windows-n0a-guest-gates.ps1','test-windows-udp-guest-gates.ps1','test-windows-udp-payload-gates.ps1'):
            self.assertIn('& ./.github/'+name,self.text)
        module=ast.parse((ROOT/'.github/windows_n0a_udp.py').read_text())
        flags=[n.value.value for n in module.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='EXECUTION_ENABLED' for t in n.targets) and isinstance(n.value,ast.Constant)]
        self.assertEqual(flags,[True])
        self.assertNotIn('--n0a-udp-runner',self.text)

    def test_exact_separate_build_pins(self):
        actor=hashlib.sha256((ROOT/'.github/native/windows_n0a_udp_actor.cpp').read_bytes()).hexdigest()
        fixture=hashlib.sha256((ROOT/'.github/native/windows_n0a_udp_fixture.cpp').read_bytes()).hexdigest()
        identity=hashlib.sha256((ROOT/'.github/native/windows_identity_actor.cpp').read_bytes()).hexdigest()
        self.assertEqual(self.text.count('-ExpectedActorSha256 '+actor),2)
        self.assertEqual(self.text.count('-ExpectedIdentitySha256 '+identity),2)
        self.assertEqual(self.text.count('-ExpectedFixtureSha256 '+fixture),1)
        for x in ('UDP_ACTOR_PIN','UDP_FIXTURE_PIN','IDENTITY_PIN'):self.assertNotIn(x,self.text)
        for x in ('udp-production-build/windows_n0a_udp_actor.exe','udp-production-build/N0A-UDP-manifest.json','udp-TEST-ONLY-build/windows_n0a_UDP_TEST_ONLY_fixture.exe','udp-TEST-ONLY-build/UDP-TEST-ONLY-manifest.json'):
            self.assertIn(x,self.text)
        line=next(x for x in self.text.splitlines() if 'python -B .github/test_windows_n0a_udp.py' in x)
        for x in ('--run-actual-windows','--production-actor','--production-manifest','--fixture-actor','--fixture-manifest','--output'):self.assertIn(x,line)
        self.assertIn('ParseFile',self.text)

    def test_document_keeps_independent_claims(self):
        text=(ROOT/'docs/validation/2026-10-21-direct-udp-mechanism.md').read_text()
        for x in ('explicit_send_denial','bounded_no_selected_udp_datagram','not delivery','not actor attribution','cannot authenticate','REQUEST3','TEST_ONLY','No artifacts'):
            self.assertIn(x,text)
        self.assertIn('precede all socket operations',text)


if __name__=='__main__':unittest.main()
