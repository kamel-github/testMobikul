odoo.define('bi_ecommerce_category_snippet.category_snippet', function (require) {
    'use strict';

    var ajax = require("web.ajax");
    var rpc = require('web.rpc');
    var publicWidget = require('web.public.widget');

    publicWidget.registry.js_category_snippet = publicWidget.Widget.extend({
        selector: ".js_category_snippet",
        start: function () {
            self = this;
            self.getSliderData();
        },
        getSliderData: function(){
            var self = this;
            var classList = self.$target.attr('class').split(/\s+/);
            var template = self.$target.data("template");
            var style_id = self.$target.data("style_id");
            ajax.jsonRpc('/category/snippet/render', 'call', {'classList': classList,'template':template,'style_id':style_id}).then(function (data) {
                $(self.$target).html(data);
                self.initOwlSlider();
            });
        },
        initOwlSlider: function () {
            $('.carousel_control_3').owlCarousel({
                loop: false,
                rewind: true,
                nav: true,
                dots: false,
                lazyLoad:true,
                navText : ['<i class="fa fa-angle-left"></i>','<i class="fa fa-angle-right"></i>'],
                autoplay: true,
                autoplayTimeout: 4000,
                autoplayHoverPause:true,
                items: 3,
                responsive: {
                    0: {
                        items: 1,
                    },
                    900: {
                        items: 2,
                    },
                    1200: {
                        items: 3,
                    },
                },
            });
            $('.carousel_control_2').owlCarousel({
                loop: false,
                rewind: true,
                nav: true,
                dots: false,
                lazyLoad:true,
                navText : ['<i class="fa fa-angle-left"></i>','<i class="fa fa-angle-right"></i>'],
                autoplay: true,
                autoplayTimeout: 4000,
                autoplayHoverPause:true,
                items: 2,
                responsive: {
                    0: {
                        items: 1,
                    },
                    900: {
                        items: 2,
                    },
                },
            });
            $('.carousel_control_4').owlCarousel({
                loop: false,
                rewind: true,
                nav: true,
                dots: true,
                lazyLoad:true,
                navText : ['<i class="fa fa-angle-left"></i>','<i class="fa fa-angle-right"></i>'],
                autoplay: true,
                autoplayTimeout: 4000,
                autoplayHoverPause:true,
                items: 3,
                responsive: {
                    0: {
                        items: 1,
                    },
                    500: {
                        items: 2,
                    },
                    900: {
                        items: 3,
                    },
                    1200: {
                        items: 4,
                    },
                },
            });
        },
    });
});
