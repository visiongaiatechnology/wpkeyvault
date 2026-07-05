/**
 * UI CONTROLLER: VISIONGAIATECHNOLOGY VAULT
 */
(function($) {
    'use strict';

    $(document).ready(function() {
        const confirmMsg = (typeof vgtVaultData !== 'undefined' && vgtVaultData.confirm_msg) 
            ? vgtVaultData.confirm_msg 
            : 'Möchten Sie diesen Key wirklich unwiderruflich löschen?';

        // Event-Abfangung für das Löschen von Verschlüsselungsknoten
        $('.vgt-delete-form').on('submit', function(e) {
            // Keine Standard-Block-Dialoge (hier absichernd mit der lokalisierten Systemwarnung)
            const proceed = window.confirm(confirmMsg);
            if (!proceed) {
                e.preventDefault();
            }
        });

        // Automatische Groß- und Kleinschreibungs-Transformation im System Identifier
        $('#key_name').on('input', function() {
            let val = $(this).val();
            // Erlaubt nur Alphanumerik, Unterstriche und Bindestriche
            let filtered = val.replace(/[^a-zA-Z0-9_\-]/g, '');
            if (val !== filtered) {
                $(this).val(filtered);
            }
        });
    });
})(jQuery);