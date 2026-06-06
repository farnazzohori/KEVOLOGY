# How to add Nuclei templates

The dashboard **does not come with templates**.  
You copy them to the server once — then click **Sync now**.

---

## Where do I put the files?

**Default folder** (inside this project):

```
DB-Exploits/nuclei-templates-main/
```

Put your Nuclei `.yaml` files there (subfolders are OK).

The exact path is also shown on the dashboard, under the KPI boxes.

---

## Easiest way — clone on the server

SSH to the server, go to this project folder, then run:

```bash
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git DB-Exploits/nuclei-templates-main
```

If the folder already exists, remove it first:

```bash
rm -rf DB-Exploits/nuclei-templates-main
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git DB-Exploits/nuclei-templates-main
```

---

## Or upload from your PC

Copy your local `nuclei-templates` folder to the server path above.

Example with SCP (change `user` and `server`):

```bash
scp -r ./nuclei-templates user@server:DB-Exploits/nuclei-templates-main
```

Run the `scp` command **from inside this project folder** on your PC,  
or use the full path on the server if you upload elsewhere.

---

## Then refresh

1. Open the Ninjas KEV dashboard  
2. Click **Sync now**  

Done. The **Nuclei** column should start showing matches.

---

## Want a different folder?

Only if the default path does not work for you:

1. Open `config.json`  
2. Change `nuclei_templates_dir` to your folder  
   - Example (inside project): `"DB-Exploits/nuclei-templates-main"`  
   - Example (anywhere on server): `"/opt/my-nuclei-templates"`  
3. Put templates in that folder  
4. Click **Sync now**

---

## Notes

- KEV list updates automatically every day.  
- Templates are **not** downloaded for you — you add them manually.  
- Empty folder = **0** Nuclei coverage in the table (that is normal until you import).
