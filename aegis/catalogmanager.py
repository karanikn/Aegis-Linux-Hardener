"""Settings catalog editor / Διαχείριση λίστας με backup και Undo."""
import json
from . import appregistry,catalog,categories,console,actions,system
from .ui import UI


@console.cancellable_menu
def menu(language,theme):
    ui=UI(language,theme)
    while True:
        choice=ui.choose('Manage App Installer list',[
            ('add','Add APT application','Choose a package, display name, category and optional regular-user launcher.'),
            ('remove','Remove entry / hide built-in','List only: never uninstalls the program. Custom entries are deleted; built-ins are hidden.'),
            ('restore','Restore hidden built-in entry','Restore a supported built-in application. Guide-only entries stay excluded.'),
            ('config','View catalog configuration','Persistent /etc/aegis-linux-hardener/app-catalog.json. Changes are backed up for Undo.')])
        if choice is None:return
        if choice=='__refresh__':continue
        try:
            if choice=='config':ui.view('App catalog configuration',json.dumps(appregistry.load(),ensure_ascii=False,indent=2));continue
            if choice=='add':
                package=appregistry.package_name(ui.prompt('APT package name','Όνομα πακέτου APT',''))
                if not catalog.package_candidate(package) and not system.installed(package):
                    ui.error('No APT candidate or installed package found. Refresh APT metadata in Maintenance and check the name.');continue
                value={'package':package,'label':ui.prompt('Display name','Όνομα στη λίστα',package),
                       'description':ui.prompt('Short description','Σύντομη περιγραφή','Custom APT application: '+package)}
                category=ui.choose('Application category',[(name,name,'Group this application by purpose.') for name,_ in categories.GROUPS])
                if not category or category=='__refresh__':continue
                value['category']=category
                value['command']=ui.prompt('Optional executable name, no arguments (blank = package contents)','Προαιρετικό εκτελέσιμο, χωρίς ορίσματα (κενό = αρχεία πακέτου)','')
            elif choice=='remove':
                rows=catalog.visible_apps()
                value=ui.choose('Remove from App Installer list',[(key,label,'Remove this list entry only. Installed package/data remain.') for key,label,*_ in rows])
                if not value or value=='__refresh__':continue
            elif choice=='restore':
                hidden=set(appregistry.load()['hidden'])-appregistry.REMOVED_GUIDES
                rows=[r for r in catalog.APPS if r[0] in hidden]
                if not rows:ui.view('Hidden entries','No hidden supported built-in entries.');continue
                value=ui.choose('Restore built-in entry',[(key,label,'Show this application in the catalog again.') for key,label,*_ in rows])
                if not value or value=='__refresh__':continue
            else:continue
            plan=appregistry.change_plan(choice,value,catalog.APPS)
            actions.apply(plan,system.ssh_connection());console.pause()
        except (console.Cancelled,KeyboardInterrupt):continue
        except Exception as error:ui.error(error)
