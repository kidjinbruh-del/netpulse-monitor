const {test,expect}=require('@playwright/test');
const base=process.env.NP_TEST_URL||'http://127.0.0.1:8770';
async function login(page,token='ci-admin'){
 await page.goto(base+'/#operations');
 await page.locator('#login-token').fill(token);
 await page.getByRole('button',{name:'Войти',exact:true}).click();
 await page.getByRole('button',{name:'Операционный центр',exact:true}).click();
 await expect(page.locator('#ops-summary')).toContainText('Открыто:');
}
test('workspace persists metadata and incident timeline',async({page})=>{
 const errors=[];page.on('pageerror',error=>errors.push(error.message));
 await login(page);
 await page.getByRole('button',{name:'Office (test fixture)',exact:true}).click();
 await page.locator('#ops-context-form [name=site]').fill('Branch A');
 await page.locator('#ops-context-form [name=owner]').fill('Helpdesk');
 await page.locator('#ops-context-form [name=tags]').fill('wan, lab');
 await page.getByRole('button',{name:'Сохранить контекст',exact:true}).click();
 await expect(page.locator('#ops-devices')).toContainText('Branch A');
 await page.reload();
 await expect(page.locator('#ops-devices')).toContainText('Branch A');
 await page.getByRole('button',{name:'Fixture connectivity check',exact:true}).click();
 await page.getByRole('button',{name:'Принять в работу',exact:true}).click();
 await expect(page.locator('#ops-incident-detail')).toContainText('acknowledged');
 await page.locator('#ops-incident-form [name=message]').fill('Browser check');
 await page.getByRole('button',{name:'Комментарий',exact:true}).click();
 await expect(page.locator('#ops-incident-detail')).toContainText('Browser check');
 expect(errors).toEqual([]);
});
test('viewer cannot configure devices or change incidents',async({page})=>{
 await login(page,'ci-viewer');
 await expect(page.locator('#ops-admin')).toBeHidden();
 await page.getByRole('button',{name:'Office (test fixture)',exact:true}).click();
 await expect(page.locator('#ops-context-form')).toHaveCount(0);
 const response=await page.request.post(base+'/api/devicesave',{
   headers:{'X-Auth':'ci-viewer'},data:{id:'not-allowed'}});
 expect(response.status()).toBe(403);
});
test('setup detects missing credentials and stores a reference',async({page})=>{
 await login(page);
 const form=page.locator('#ops-setup-form');
 await form.locator('[name=id]').fill('second');
 await form.locator('[name=name]').fill('Second lab');
 await form.locator('[name=url]').fill('https://second.invalid');
 await form.locator('[name=username]').fill('readonly');
 await form.locator('[name=password_env]').fill('NP_BROWSER_ABSENT_PASSWORD');
 await page.getByRole('button',{name:'Проверить подключение',exact:true}).click();
 await expect(page.locator('#ops-setup-status')).toContainText('Проверьте',{timeout:20000});
 await page.getByRole('button',{name:'Сохранить устройство',exact:true}).click();
 await expect(page.locator('#ops-setup-status')).toContainText('Настройки сохранены');
 await expect(page.locator('#ops-devices')).toContainText('Second lab');
});

test('administrator creates and verifies a consistent backup',async({page})=>{
 await login(page);
 await page.getByRole('button',{name:'Настройки',exact:true}).click();
 await page.getByRole('button',{name:'Копия сейчас',exact:true}).click();
 await expect(page.locator('#settings-status')).toContainText('Копия создана:',{timeout:30000});
 await page.getByRole('button',{name:'Проверить архив',exact:true}).click();
 await expect(page.locator('#settings-status')).toContainText('Архив исправен.',{timeout:30000});
});
