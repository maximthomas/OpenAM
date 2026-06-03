/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2015-2016 ForgeRock AS.
 */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
declare const JSONEditor: any;

import _ from "lodash";
import i18n from "@/i18n";

function buildTitaToggle(checkbox: HTMLInputElement, gridColWidth1: number): HTMLDivElement {
  const div = document.createElement("div");
  const container = document.createElement("div");
  const label = document.createElement("label");
  const span = document.createElement("span");
  checkbox.style.width = "1px";
  checkbox.style.height = "1px";
  label.appendChild(checkbox);
  label.appendChild(span);
  div.setAttribute(
    "class",
    `checkbox checkbox-slider-primary checkbox-slider checkbox-slider--b-flat`
  );
  div.style.marginTop = "-5px";
  div.appendChild(label);
  container.setAttribute("class", `col-sm-${gridColWidth1}`);
  container.appendChild(div);
  return container;
}

export function getTheme(gridColWidth1: number, gridColWidth2: number): typeof JSONEditor.AbstractTheme {
  const gridColWidth3 = 12 - gridColWidth2;

  const theme = JSONEditor.AbstractTheme.extend({
    getSelectInput(options: HTMLOptionElement[]): HTMLSelectElement {
      const input = this._super(options);
      input.className += "form-control";
      return input;
    },

    setSelectOptions(
      selectGroup: HTMLElement,
      options: string[],
      titles?: string[]
    ): void {
      const select =
        selectGroup.getElementsByTagName("select")[0] || selectGroup;
      titles = titles || [];
      select.innerHTML = "";

      for (let i = 0; i < options.length; i++) {
        const option = document.createElement("option");
        option.setAttribute("value", options[i]);
        option.textContent = titles[i] || options[i];
        select.appendChild(option);
      }
    },

    setGridColumnSize(): void {
      // JSONEditor grid system not used, so overridden here.
    },

    afterInputReady(input: HTMLElement & { controlgroup?: HTMLElement }): void {
      if (input.controlgroup) {
        return;
      }
      input.controlgroup = this.closest(input, ".form-group") as HTMLElement;
      if (this.closest(input, ".compact")) {
        input.controlgroup!.style.marginBottom = "0";
      }
    },

    getTextareaInput(placeholder?: string): HTMLTextAreaElement {
      const el = document.createElement("textarea");
      el.className = "form-control";
      if (placeholder) {
        el.setAttribute("placeholder", placeholder);
      }
      return el;
    },

    getFormInputField(type: string, placeholder?: string): HTMLInputElement {
      const input = this._super(type);
      if (type !== "checkbox") {
        input.className += "form-control";
      }
      if (placeholder) {
        input.setAttribute("placeholder", placeholder);
      }
      input.setAttribute("autocomplete", "off");
      return input;
    },

    getFormInputLabel(text: string): HTMLLabelElement {
      const el = document.createElement("label");
      el.appendChild(document.createTextNode(text));
      el.className += ` control-label col-sm-${gridColWidth2}`;
      return el;
    },

    getFormControl(
      label: HTMLLabelElement,
      input: HTMLElement,
      description?: HTMLElement,
      inheritanceButton?: HTMLElement
    ): HTMLDivElement {
      const group = document.createElement("div");
      const div = document.createElement("div");

      group.className = "form-group";

      if (label && (input as HTMLInputElement).type === "checkbox") {
        input = buildTitaToggle(input as HTMLInputElement, gridColWidth1);
        (input as HTMLElement).style.marginTop = "12px";
      }

      if (label) {
        label.className += ` control-label col-sm-${gridColWidth2}`;
        group.appendChild(label);
      }

      if (
        input.nodeName.toLowerCase() === "input" ||
        input.nodeName.toLowerCase() === "select"
      ) {
        div.className += `col-sm-${gridColWidth1}`;
        div.appendChild(input);
        group.appendChild(div);
      } else {
        group.appendChild(input);
      }

      if (inheritanceButton) {
        group.appendChild(inheritanceButton);
      }

      if (description) {
        group.appendChild(description);
      }
      return group;
    },

    getCheckboxLabel(text: string): HTMLLabelElement {
      return this.getFormInputLabel(text);
    },

    getIndentedPanel(): HTMLDivElement {
      return document.createElement("div");
    },

    getFormInputDescription(text: string): HTMLElement {
      return this.getDescription(text);
    },

    getDescription(text: string): HTMLDivElement {
      const el = document.createElement("div");
      const parseHtml = document.implementation.createHTMLDocument("");
      el.className = `col-sm-offset-${gridColWidth2} col-sm-${gridColWidth3} help-block`;
      parseHtml.body.innerHTML = `<div class='wordwrap'>${text}</div>`;
      el.appendChild(parseHtml.body.getElementsByTagName("div")[0]);
      return el;
    },

    getHeaderButtonHolder(): HTMLDivElement {
      return this.getButtonHolder();
    },

    getButtonHolder(): HTMLDivElement {
      const el = document.createElement("div");
      el.className = "btn-group";
      return el;
    },

    getButton(text: string, icon?: HTMLInputElement, title?: string): HTMLButtonElement {
      const el = this._super(text, icon, title);
      el.className += "btn btn-default";
      return el;
    },

    getInlineButton(text: string, icon?: HTMLInputElement, title?: string): HTMLButtonElement {
      const el = this._super(text, icon, title);
      el.className += "btn btn-link delete-row-item";
      return el;
    },

    getTable(): HTMLTableElement {
      const el = document.createElement("table");
      el.className = "table table-bordered";
      el.style.width = "auto";
      el.style.maxWidth = "none";
      return el;
    },

    getGridRow(): HTMLDivElement {
      const el = document.createElement("div");
      el.className = "form-horizontal";
      return el;
    },

    addInputError(input: HTMLElement & { controlgroup?: HTMLElement; errmsg?: HTMLElement }, text: string): void {
      if (!input.controlgroup) {
        return;
      }
      input.controlgroup.className += " has-error";
      if (!input.errmsg) {
        input.errmsg = document.createElement("p");
        input.errmsg.className =
          `help-block errormsg col-sm-offset-${gridColWidth2} col-sm-${gridColWidth1}`;
        input.controlgroup.appendChild(input.errmsg);
      } else {
        input.errmsg.style.display = "";
      }
      input.errmsg.textContent = text;
    },

    removeInputError(input: HTMLElement & { errmsg?: HTMLElement; controlgroup?: HTMLElement }): void {
      if (!input.errmsg) {
        return;
      }
      input.errmsg.style.display = "none";
      input.controlgroup!.className = input.controlgroup!.className.replace(
        /\s?has-error/g,
        ""
      );
    },

    getTabHolder(): HTMLDivElement {
      const el = document.createElement("div");
      el.innerHTML =
        "<div class=tabs 'list-group col-md-2'></div><div class='col-md-10'></div>";
      el.className = "rows";
      return el;
    },

    getTab(text: string | Node): HTMLAnchorElement {
      const el = document.createElement("a");
      el.className = "list-group-item";
      el.setAttribute("href", "#");
      if (typeof text === "string") {
        el.appendChild(document.createTextNode(text));
      } else {
        el.appendChild(text);
      }
      return el;
    },

    markTabActive(tab: HTMLElement): void {
      tab.className += " active";
    },

    markTabInactive(tab: HTMLElement): void {
      tab.className = tab.className.replace(/\s?active/g, "");
    },

    getProgressBar(): HTMLDivElement {
      const container = document.createElement("div");
      const bar = document.createElement("div");
      container.className = "progress";
      bar.className = "progress-bar";
      bar.setAttribute("role", "progressbar");
      bar.setAttribute("aria-valuenow", "0");
      bar.setAttribute("aria-valuemin", "0");
      bar.setAttribute("aria-valuemax", "100");
      bar.innerHTML = "0%";
      container.appendChild(bar);
      return container;
    },

    updateProgressBar(progressBar: HTMLElement, progress: number): void {
      if (!progressBar) {
        return;
      }
      const bar = progressBar.firstChild as HTMLElement;
      const percentage = `${progress}%`;
      bar.setAttribute("aria-valuenow", String(progress));
      bar.style.width = percentage;
      bar.innerHTML = percentage;
    },

    updateProgressBarUnknown(progressBar: HTMLElement): void {
      if (!progressBar) {
        return;
      }
      const bar = progressBar.firstChild as HTMLElement;
      progressBar.className = "progress progress-striped active";
      bar.removeAttribute("aria-valuenow");
      bar.style.width = "100%";
      bar.innerHTML = "";
    },

    getFirstColumnWrapper(): HTMLDivElement {
      const wrapper = document.createElement("div");
      wrapper.className = `col-sm-${gridColWidth1}`;
      return wrapper;
    },

    getSecondColumnWrapper(): HTMLDivElement {
      const wrapper = document.createElement("div");
      wrapper.className = `col-sm-offset-1 col-sm-${gridColWidth2 - 1}`;
      return wrapper;
    },

    addError(element: HTMLElement): void {
      element.classList.add("has-error");
    },

    removeError(element: HTMLElement): void {
      element.classList.remove("has-error");
    },

    addBorder(element: HTMLElement): void {
      element.style.border = "solid 1px rgb(204, 204, 204)";
      element.style.marginBottom = "15px";
    },

    getHeader(text: string): HTMLHeadingElement {
      const el = document.createElement("h3");
      el.className = "block-header";
      el.setAttribute("data-header", "true");
      if (typeof text === "string") {
        el.textContent = text;
      }
      return el;
    },

    getMapHeader(text: string): HTMLDivElement {
      const el = document.createElement("div");
      const header = document.createElement("label");
      el.appendChild(header);
      if (typeof text === "string") {
        header.textContent = text;
      }
      el.style.display = "inline-block";
      el.className = "col-sm-offset-1";
      return el;
    },

    getKeyFormInputField(): HTMLInputElement {
      return this.getFormInputField("text", i18n.global.t("common.form.key"));
    },

    getValueFormInputField(): HTMLInputElement {
      return this.getFormInputField("text", i18n.global.t("common.form.value"));
    },

    getInputId(): string {
      return _.uniqueId();
    },

    getInheritanceButton(
      valueIsInherited: boolean,
      path: string
    ): HTMLButtonElement {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "btn fr-btn-secondary am-btn-single-icon";
      button.setAttribute("data-inherit-value", String(valueIsInherited));
      button.setAttribute("data-schemapath", path);
      button.setAttribute("data-toggle", "button");
      button.title = i18n.global.t("common.form.inheritValue");
      const icon = document.createElement("i");
      icon.className = "fa fa-unlock";
      if (valueIsInherited) {
        button.className += " active";
        icon.className = "fa fa-lock";
      }
      button.appendChild(icon);
      return button;
    },

    getSwitcher(): HTMLDivElement {
      return document.createElement("div");
    },

    getModal(): HTMLDivElement {
      const el = document.createElement("div");
      el.className = "form-group";
      return el;
    },
  });

  return theme;
}
