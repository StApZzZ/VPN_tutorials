"""Exercise the shipped archive installation tasks with real local Ansible."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT=Path(__file__).resolve().parents[1]
loader=importlib.util.spec_from_file_location("panel_packer",ROOT/"deploy/ansible/roles/app/files/pack_panel.py")
packer=importlib.util.module_from_spec(loader);loader.loader.exec_module(packer)


@unittest.skipUnless(shutil.which("ansible-playbook"),"real Ansible is exercised in the deploy CI job")
class SourceUpgradeTests(unittest.TestCase):
    def test_changed_content_replaces_equal_timestamp_files_and_keeps_env(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            source,packed,state,installed=[root/name for name in ("source","packed","state","installed")]
            for directory in (source,packed,state,installed):directory.mkdir()
            (source/"main.py").write_text("value = 1\n")
            (installed/".env").write_text("PRIVATE_RUNTIME=keep\n")
            all_tasks=yaml.safe_load((ROOT/"deploy/ansible/roles/app/tasks/main.yml").read_text())
            tasks=[task for task in all_tasks if task["name"] in ("App | Content-checked source archive","App | Verify installed source content","App | Install changed panel sources")]
            self.assertEqual(len(tasks),3)
            # Run the production content logic under the unprivileged CI user.
            tasks[0]["ansible.builtin.copy"].update(owner=str(os.getuid()),group=str(os.getgid()))
            play=[{"name":"Source upgrade regression","hosts":"localhost","gather_facts":False,"vars":{"app_pack_dir":{"path":str(packed)},"vpn_panel_state_dir":str(state),"vpn_panel_app_dir":str(installed)},"tasks":tasks,"handlers":[{"name":"App | restart panel","ansible.builtin.debug":{"msg":"restart needed"}}]}]
            play_path=root/"play.yml";play_path.write_text(yaml.safe_dump(play))
            def deploy():
                packer.pack(str(source),str(packed/"panel.tar.gz"))
                result=subprocess.run(["ansible-playbook","-i","localhost,","-c","local",str(play_path)],capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
                return result.stdout
            deploy();first_mtime=(installed/"main.py").stat().st_mtime
            (source/"main.py").write_text("value = 2\n")
            deploy()
            self.assertEqual((installed/"main.py").read_text(),"value = 2\n")
            self.assertEqual((installed/"main.py").stat().st_mtime,first_mtime)
            self.assertIn("changed=0",deploy())
            (installed/"main.py").write_text("value = 9\n")
            deploy()
            self.assertEqual((installed/"main.py").read_text(),"value = 2\n")
            self.assertEqual((installed/".env").read_text(),"PRIVATE_RUNTIME=keep\n")


if __name__=="__main__":unittest.main()
