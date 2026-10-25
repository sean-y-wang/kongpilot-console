// Drive the actual KongSchemaForm DOM. No FormStore injection, evaluate/setValue,
// API mutation, schema rewriting, or screenshot of an open material form.
export function formFieldEntries(schema, root = false) {
  const fields = Array.isArray(schema.fields) ? schema.fields.flatMap(row => Object.entries(row)) : Object.entries(schema.fields ?? {});
  return fields.filter(([name, field]) => !field.read_only && !(root && ['id', 'created_at', 'updated_at'].includes(name)));
}
export function schemaDomKind(field) {
  if (field.type === 'record') return formFieldEntries(field).length ? 'record' : 'json';
  if (field.type === 'map') return 'map';
  if (['array', 'set'].includes(field.type)) return ['record', 'map', 'array', 'set', 'foreign', 'boolean'].includes(field.elements?.type)
    || field.type === 'array' && field.elements?.type === 'string' && !field.elements.one_of && !field.elements.enum ? 'list' : 'select-list';
  if (field.type === 'foreign' || field.reference) return 'foreign';
  if (field.type === 'boolean') return 'switch';
  if (field.one_of || field.enum) return 'select';
  return 'input';
}
export function schemaMarker(path) { return `schema-field-${path.join('-')}`; }
export function assertSchemaInput(schema, values, root = true) {
  if (!values || typeof values !== 'object' || Array.isArray(values)) throw Error('UI_SCHEMA_RECORD_INPUT_REQUIRED');
  const fields = new Map(formFieldEntries(schema, root));
  for (const [name, value] of Object.entries(values)) {
    const field = fields.get(name); if (!field || value === undefined) throw Error('UI_SCHEMA_UNKNOWN_OR_UNDEFINED_FIELD');
    if (field.type === 'record' && formFieldEntries(field).length) assertSchemaInput(field, value, false);
    if (['array', 'set'].includes(field.type)) {
      if (!Array.isArray(value)) throw Error('UI_SCHEMA_ARRAY_REQUIRED');
      if (field.elements?.type==='record' && formFieldEntries(field.elements).length) for(const item of value) assertSchemaInput(field.elements,item,false);
    }
    if (field.type === 'map' && (!value || typeof value !== 'object' || Array.isArray(value))) throw Error('UI_SCHEMA_MAP_REQUIRED');
    if (field.type === 'foreign' && (!value || typeof value.id !== 'string' || Object.keys(value).join() !== 'id')) throw Error('UI_SCHEMA_FOREIGN_ID_REQUIRED');
  }
}
export function schemaUiTrace(schema, values, basePath=[]) {
  assertSchemaInput(schema,values,basePath.length===0);const result=[];
  function visit(field,value,path){const kind=schemaDomKind(field);result.push({path,kind,marker:schemaMarker(path)});
    if(kind==='record')for(const[name,item]of Object.entries(value))visit(new Map(formFieldEntries(field)).get(name),item,[...path,name]);
    if(kind==='map')for(const[index,[,item]]of Object.entries(value).entries())visit(field.values??{type:'string'},item,[...path,index,'value']);
    if(kind==='list')for(const[index,item]of value.entries())if(field.elements?.type==='record')for(const[name,child]of Object.entries(item))visit(new Map(formFieldEntries(field.elements)).get(name),child,[...path,index,name]);else visit(field.elements??{type:'string'},item,[...path,index]);
  }
  for(const[name,value]of Object.entries(values))visit(new Map(formFieldEntries(schema)).get(name),value,[...basePath,name]);return result;
}
export async function chooseUiOption(page, input, text, expect) {
  await expect(input).toHaveCount(1);
  const select = input.locator('xpath=ancestor::*[contains(concat(" ",normalize-space(@class)," ")," ant-select ")][1]');
  const selected=select.locator('.ant-select-selection-item');
  if(await selected.count()===1&&(await selected.innerText()).trim()===text)return;
  if (await input.getAttribute('aria-expanded') !== 'true') await select.locator('.ant-select-selector').click();
  // Foreign lookups display a known ID / short suffix, enum controls display the
  // exact value. Never select the first result or a similarly named entity.
  const option = page.locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option').filter({has:page.getByText(text,{exact:true})});
  if(await option.count()===0&&await input.getAttribute('readonly')===null){
    await input.fill(text.split(' · ')[0]);await expect(option).toHaveCount(1);
  }
  for(let i=0;await option.count()===0&&i<40;i++){
    const holder=page.locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .rc-virtual-list-holder');
    if(await holder.count()!==1)break;
    await holder.hover();await page.mouse.wheel(0,240);await page.waitForTimeout(50);
  }
  await expect(option).toHaveCount(1); await option.click();
}
export async function fillSchemaUi(page, root, schema, values, expect, basePath = [], trace = [], foreignLabels = new Map()) {
  assertSchemaInput(schema, values, basePath.length === 0);
  async function visit(field, value, path, name) {
    const wrapper = root.getByTestId(schemaMarker(path)); await expect(wrapper).toHaveCount(1);
    // Descendant Collapse has forceRender, but controls remain hidden until each
    // enclosing record is expanded with a real click.
    const ancestors = wrapper.locator('xpath=ancestor::*[contains(concat(" ",normalize-space(@class)," ")," ant-collapse-item ")]');
    for (let index = 0; index < await ancestors.count(); index++) {
      const header = ancestors.nth(index).locator(':scope > .ant-collapse-header');
      if (await header.getAttribute('aria-expanded') === 'false') await header.click();
    }
    const kind = schemaDomKind(field); trace.push({path:[...path],kind});
    if (kind === 'record') {
      const header = wrapper.locator(':scope > .ant-collapse > .ant-collapse-item > .ant-collapse-header');
      if (await header.getAttribute('aria-expanded') === 'false') await header.click();
      for (const [child, childValue] of Object.entries(value)) await visit(new Map(formFieldEntries(field)).get(child), childValue, [...path,child], child);
    } else if (kind === 'map') {
      let rows = wrapper.locator(':scope > .schema-map-row');
      while (await rows.count()) await rows.last().getByRole('button',{name:`删除 ${name} 项`,exact:true}).click();
      for (const [key, childValue] of Object.entries(value)) {
        await wrapper.locator(':scope > button').filter({hasText:'添加键值项'}).click();
        const index = await rows.count()-1, row = rows.nth(index);
        await row.getByLabel(`${name} key`,{exact:true}).fill(key);
        await visit(field.values ?? {type:'string'}, childValue, [...path,index,'value'],'value');
      }
    } else if (kind === 'list') {
      const rows = wrapper.locator(':scope > .schema-array-row');
      while (await rows.count()) await rows.last().locator(':scope > .schema-array-row-heading').getByRole('button',{name:/移\s*除/}).click();
      for (const [index, item] of value.entries()) {
        await wrapper.locator(':scope > button').filter({hasText:'添加一项'}).click();
        await expect(rows).toHaveCount(index+1);
        if (field.elements?.type === 'record') for (const [child, childValue] of Object.entries(item)) await visit(new Map(formFieldEntries(field.elements)).get(child),childValue,[...path,index,child],child);
        else await visit(field.elements ?? {type:'string'},item,[...path,index],'item');
      }
    } else if (kind === 'switch') {
      const input = wrapper.getByRole('switch',{name,exact:true});
      if ((await input.getAttribute('aria-checked') === 'true') !== value) await input.click();
      await expect(input).toHaveAttribute('aria-checked',String(value));
    } else if (kind === 'foreign') {
      const input = wrapper.getByLabel(name,{exact:true}).and(wrapper.locator('input[role="combobox"]'));
      await input.fill(value.id);
      // Exact ID search returns a DTO whose rendered label is name · short ID.
      // Caller supplies a protected readback-derived label; IDs never come from
      // fuzzy first-result matching.
      const label = foreignLabels.get(value.id);
      if (!label) throw Error('UI_FOREIGN_PROTECTED_LABEL_MISSING');
      await chooseUiOption(page,input,label,expect);
    } else if (kind === 'select' || kind === 'select-list') {
      const input = wrapper.getByLabel(name,{exact:true}).and(wrapper.locator('input[role="combobox"]'));
      if (kind === 'select') await chooseUiOption(page,input,String(value),expect);
      else {
        const selected = wrapper.locator('.ant-select-selection-item-remove');
        while (await selected.count()) await selected.last().click();
        for (const item of value) {
          if (field.elements?.one_of || field.elements?.enum) await chooseUiOption(page,input,String(item),expect);
          else { await input.fill(String(item)); await input.press('Enter'); }
        }
        await input.press('Escape');
      }
    } else await wrapper.getByLabel(name,{exact:true}).fill(kind === 'json' ? JSON.stringify(value) : value === null ? '' : String(value));
  }
  for (const [name,value] of Object.entries(values)) await visit(new Map(formFieldEntries(schema)).get(name),value,[...basePath,name],name);
  return trace;
}
