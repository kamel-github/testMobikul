odoo.define('bi_ecommerce_category_snippet.category_snippet_editor', function (require) {
'use strict';

    var core = require('web.core');
    var rpc = require('web.rpc');
    var weContext = require('web_editor.context');
    var options = require('web_editor.snippets.options');
    var wUtils = require('website.utils');
    var Wysiwyg = require('web_editor.wysiwyg');
    var _t = core._t;

        Wysiwyg.include({
            start: function () {
                return this._super.apply(this, arguments);
            },
            /**
            * @override
            */
            _saveElement: async function ($el, context, withLang) {
                var promises = [];

                // Saving a view content
                await this._super.apply(this, arguments);

                // Saving mega menu options
                if ($el.data('oe-field') === 'mega_menu_content') {
                    // On top of saving the mega menu content like any other field
                    // content, we must save the custom classes that were set on the
                    // menu itself.
                    // FIXME normally removing the 'show' class should not be necessary here
                    // TODO check that editor classes are removed here as well
                    var classes = _.without($el.attr('class').split(' '), 'dropdown-menu', 'o_mega_menu', 'show');
                    promises.push(this._rpc({
                        model: 'website.menu',
                        method: 'write',
                        args: [
                            [parseInt($el.data('oe-id'))],
                            {
                                'mega_menu_classes': classes.join(' '),
                            },
                        ],
                    }));
                }

                // Saving cover properties on related model if any
                var prom = this._saveCoverProperties($el);
                if (prom) {
                    promises.push(prom);
                }

                return Promise.all(promises);
            }
        });
});
