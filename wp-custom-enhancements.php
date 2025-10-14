<?php
/*
Plugin Name: WP Custom Enhancements
Description: Improves speed and security, removes unnecessary features, adds multiple layers of protection against common attack vectors.
Author: ITarchitects
Version: 1.0
*/

if (! defined('ABSPATH')) {
    exit;
} // Prevent direct access


/* =====================================================
    Security Hardening
===================================================== */

// Block Rest API user & sensitive endpoints for unauthenticated users (Comment this out if using Jeff Stars plugin)
add_filter('rest_pre_dispatch', function ($result, $wp_rest_server, $request) {
    if (is_user_logged_in()) {
        return $result;
    }

    $route = $request->get_route();
    $blocked_prefixes = [
        '/wp/v2/users',
        '/wp/v2/comments',
        '/wp/v2/settings',
        '/oembed/1.0/proxy',
    ];

    foreach ($blocked_prefixes as $prefix) {
        if (strpos($route, $prefix) === 0) {
            return new WP_Error(
                'rest_forbidden',
                __('You are not allowed to access this endpoint.', 'itarchitects'),
                ['status' => 403]
            );
        }
    }

    return $result;
}, 10, 3);

// Disable built-in theme & plugin file editors
if (! defined('DISALLOW_FILE_EDIT')) {
    define('DISALLOW_FILE_EDIT', true);
}

// Disable Gutenberg (Block Editor)
add_filter('use_block_editor_for_post_type', '__return_false', 10);

// Disable Application Passwords
add_filter('wp_is_application_passwords_available', '__return_false');

// Remove Language Switcher
add_filter('login_display_language_dropdown', '__return_false');

// Remove xmlrpc
add_filter('xmlrpc_enabled', '__return_false');

// Generic login error messages (no username hints)
add_filter('login_errors', function () {
    return __('Login failed: Please check your credentials.', 'itarchitects');
});

// User enumeration & author archive blocking
add_action('template_redirect', function () {
    if (is_admin()) {
        return;
    }

    // Block author archives & numeric author queries
    if (is_author() || get_query_var('author_name') || get_query_var('author')) {
        wp_safe_redirect(home_url(), 301);
        exit;
    }
});


/* =====================================================
    Head Cleanup & Meta Removal
===================================================== */

// Remove WordPress branding
add_action('wp_before_admin_bar_render', function () {
    if (! is_admin_bar_showing()) {
        return;
    }
    global $wp_admin_bar;
    $wp_admin_bar->remove_menu('wp-logo');
}, 0);

add_filter('admin_title', function ($admin_title, $title) {
    return str_replace(' &#8212; WordPress', '', $admin_title);
}, 10, 2);

// Remove unwanted meta tags/links
add_filter('show_recent_comments_widget_style', '__return_false');
add_filter('use_default_gallery_style', '__return_false');
remove_action('wp_head', 'wlwmanifest_link'); // Windows Live Writer
remove_action('wp_head', 'rsd_link');         // Really Simple Discovery
remove_action('wp_head', 'wp_generator');     // WP version
add_filter('the_generator', '__return_empty_string');

// Remove shortlinks (head + HTTP headers)
remove_action('wp_head', 'wp_shortlink_wp_head', 10, 0);
add_filter('after_setup_theme', function () {
    remove_action('template_redirect', 'wp_shortlink_header', 11, 0);
});


/* =====================================================
    Script & Asset Cleanup
===================================================== */

// Disable block-related frontend CSS
add_action('wp_enqueue_scripts', function () {
    wp_dequeue_style('wp-block-library');
    wp_dequeue_style('wp-block-library-theme');
    wp_dequeue_style('global-styles');
}, 20);

// Remove WP/WooCommerce password strength meter where not needed
add_action('wp_print_scripts', function () {
    $load_meter = false;
    if (function_exists('is_account_page') && is_account_page()) $load_meter = true;
    if (function_exists('is_checkout') && is_checkout()) $load_meter = true;
    if (is_page(['reset-password', 'my-account', 'checkout'])) $load_meter = true;

    if (! $load_meter) {
        wp_dequeue_script('zxcvbn-async');
        wp_dequeue_script('password-strength-meter');
        wp_dequeue_script('wc-password-strength-meter');
    }
}, 100);


/* =====================================================
    Comments Disable
===================================================== */

add_action('admin_init', function () {
    if (! current_user_can('moderate_comments')) {
        return;
    }

    $screen = function_exists('get_current_screen') ? get_current_screen() : null;
    if ($screen && $screen->id === 'edit-comments') {
        wp_safe_redirect(admin_url());
        exit;
    }

    remove_meta_box('dashboard_recent_comments', 'dashboard', 'normal');

    foreach (get_post_types() as $post_type) {
        if (post_type_supports($post_type, 'comments')) {
            remove_post_type_support($post_type, 'comments');
            remove_post_type_support($post_type, 'trackbacks');
        }
    }
});

add_filter('comments_open', '__return_false', 20, 2);
add_filter('pings_open', '__return_false', 20, 2);
add_filter('comments_array', '__return_empty_array', 10, 2);

add_action('admin_menu', function () {
    if (current_user_can('moderate_comments')) {
        remove_menu_page('edit-comments.php');
    }
});

add_action('init', function () {
    if (is_admin_bar_showing()) {
        remove_action('admin_bar_menu', 'wp_admin_bar_comments_menu', 60);
    }
});


/* =====================================================
    Embeds Disable
===================================================== */

add_action('init', function () {
    remove_action('rest_api_init', 'wp_oembed_register_route');
    add_filter('embed_oembed_discover', '__return_false');
    remove_filter('oembed_dataparse', 'wp_filter_oembed_result', 10);
    remove_action('wp_head', 'wp_oembed_add_discovery_links');
    remove_action('wp_head', 'wp_oembed_add_host_js');

    add_filter('tiny_mce_plugins', function ($plugins) {
        return is_array($plugins) ? array_diff($plugins, ['wpembed']) : [];
    });

    add_filter('rewrite_rules_array', function ($rules) {
        foreach ($rules as $rule => $rewrite) {
            if (false !== strpos($rewrite, 'embed=true')) {
                unset($rules[$rule]);
            }
        }
        return $rules;
    });

    remove_filter('pre_oembed_result', 'wp_filter_pre_oembed_result', 10);
}, 9999);


/* =====================================================
    Emojis Disable
===================================================== */

add_action('init', function () {
    remove_action('wp_head', 'print_emoji_detection_script', 7);
    remove_action('admin_print_scripts', 'print_emoji_detection_script');
    remove_action('wp_print_styles', 'print_emoji_styles');
    remove_action('admin_print_styles', 'print_emoji_styles');
    remove_filter('the_content_feed', 'wp_staticize_emoji');
    remove_filter('comment_text_rss', 'wp_staticize_emoji');
    remove_filter('wp_mail', 'wp_staticize_emoji_for_email');

    add_filter('tiny_mce_plugins', function ($plugins) {
        return is_array($plugins) ? array_diff($plugins, ['wpemoji']) : [];
    });

    // Remove DNS prefetch for emoji CDN
    add_filter('wp_resource_hints', function ($urls, $relation_type) {
        if ('dns-prefetch' === $relation_type) {
            $emoji_svg_url = apply_filters('emoji_svg_url', 'https://s.w.org/images/core/emoji/2/svg/');
            $urls = array_diff($urls, [$emoji_svg_url]);
        }
        return $urls;
    }, 10, 2);
});


/* =====================================================
    Search Disable
===================================================== */

add_action('parse_query', function ($query, $error = true) {
    if (is_admin()) {
        return;
    }
    if ($query->is_main_query() && $query->is_search()) {
        $query->is_search       = false;
        $query->query_vars['s'] = false;
        $query->query['s']      = false;
        if ($error === true) {
            $query->is_404 = true;
        }
    }
}, 15, 2);

add_action('widgets_init', function () {
    unregister_widget('WP_Widget_Search');
});
add_filter('get_search_form', '__return_empty_string', 999);
add_action('init', function () {
    if (class_exists('WP_Block_Type_Registry')) {
        $block = 'core/search';
        if (WP_Block_Type_Registry::get_instance()->is_registered($block)) {
            unregister_block_type($block);
        }
    }
});
add_action('admin_bar_menu', function ($wp_admin_bar) {
    $wp_admin_bar->remove_menu('search');
}, 11);


/* =====================================================
    RSS Disable
===================================================== */

function disable_rss_feeds()
{
    if (is_admin()) {
        return;
    }
    wp_safe_redirect(home_url(), 301);
    exit;
}
add_action('do_feed', 'disable_rss_feeds', 1);
add_action('do_feed_rdf', 'disable_rss_feeds', 1);
add_action('do_feed_rss', 'disable_rss_feeds', 1);
add_action('do_feed_rss2', 'disable_rss_feeds', 1);
add_action('do_feed_atom', 'disable_rss_feeds', 1);
add_action('do_feed_rss2_comments', 'disable_rss_feeds', 1);
add_action('do_feed_atom_comments', 'disable_rss_feeds', 1);

remove_action('wp_head', 'feed_links', 2);
remove_action('wp_head', 'feed_links_extra', 3);


