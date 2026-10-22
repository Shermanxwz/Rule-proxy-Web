"""B profile pointer and predecessor gates, using inert native fakes only."""
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('b_fixtures',Path(__file__).with_name('test_windows_identity_model2_ownership.py'))
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
m=f.m;l=f.l
B='S-1-15-2-8-9-10-11-12-13-14'


class WrongPeerTests(unittest.TestCase):
    def owner(self,root,api):
        c=f.config();c.update(execution_mode='profiles-off-diagnostic',selected_admission=dict(
            profile='actor-plus-system-conhost-v1',conhost_sha256='f'*64),wrong_peer_extension=dict(profile='wrong-peer-psec-control-v1',
            **{key:format(i,'032x') for i,key in enumerate(('listener_boot','control_boot','control_admission','before_case','wrong_case','after_case'),20)}))
        return m.FirstController(c,root,api)

    def test_b_constructor_uses_only_exact_owned_b_pointer_and_rejects_copied_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);exe=root/'actor.exe';exe.write_bytes(b'fixture')
            api=f.Clock();api.process_info=lambda:SimpleNamespace(hProcess=None,hThread=None)
            calls=[]
            def create(*args):calls.append(args[6]);raise ValueError('fake_create_stop')
            api.pncs_create=create
            owner=self.owner(root,api);owner.config['actor_sha256']=l.sha(b'fixture')
            owner.profile.update(created=True,returned=True,pointer=11,sid=f.AC)
            owner.b_profile.update(created=True,returned=True,pointer=22,sid=B)
            with self.assertRaisesRegex(ValueError,'fake_create_stop'):
                owner.task('b-listener',[str(exe)],root,profile=B,profile_record=owner.b_profile)
            self.assertEqual(calls,[22])
            with self.assertRaisesRegex(ValueError,'owned_profile_pointer'):
                owner.task('b-invalid',[str(exe)],root,profile=B,profile_record=dict(owner.b_profile))
            self.assertEqual(calls,[22])

    def test_b_cannot_create_or_bind_until_original_front_and_relay_are_verified_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            api=f.Clock();owner=self.owner(Path(temporary),api);owner.tasks={'front':dict(exited=False,exit_code=None),'relay':dict(exited=True,exit_code=0)}
            owner.value['checks']['positive']=True
            with self.assertRaisesRegex(ValueError,'a_front_closed_before_b'):
                owner.wrong_peer_setup(Path('actor.exe'),dict(proxy=51001,wrong_port=51002,origin=51003),'fixed')
            self.assertFalse(owner.b_profile['attempted'])
            self.assertFalse(owner.b_profile_ledger['attempted'])
            self.assertEqual(list(Path(temporary).iterdir()),[])


if __name__=='__main__':unittest.main()
