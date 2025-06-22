# ex: si ts=4 sw=4 et

define shorewall::rule (
    Optional[String]                                                $application   = '',
    Optional[Pattern[/^(([0-9]+|tcp|udp|icmp|-)(?:,|$))+/]]         $proto  = '',
    Optional[Pattern[/^:?[0-9]+:?$/, /^-$/, /^[0-9]+[:,][0-9]+$/]]  $port   = '',
    Optional[String]                                                $sport  = '',
    Optional[String]                                                $original_dest = '',
    String                                                          $source,
    String                                                          $dest,
    String                                                          $action,
    Optional[Boolean]                                               $ipv4   = $::shorewall::ipv4,
    Optional[Boolean]                                               $ipv6   = $::shorewall::ipv6,
    Integer                                                         $order  = 50,
) {
    if $application == '' {
        #validate_re($proto, '^(([0-9]+|tcp|udp|icmp|-)(?:,|$))+')
        validate_legacy(Pattern[/^(([0-9]+|tcp|udp|icmp|-)(?:,|$))+/], 'validate_legacy', $proto, '^\d+$', 'Wrong proto')
        #validate_re($port, ['^:?[0-9]+:?$', '^-$', '^[0-9]+[:,][0-9]+$'])
        if $port !~ Pattern['^:?[0-9]+:?$', '^-$', '^[0-9]+[:,][0-9]+$'] {
            fail("Port '$port'")
        }
    } else {
        #validate_re($application, '^[[:alnum:]]+$')
        if $application !~ String {
            fail("Port '$port'")
        }
        #validate_re($proto, '^-?$')
        if $proto !~ '^-?$' {
            fail("Proto '$proto'")
        }
        #validate_re($port, '^-?$')
        if $port !~ '^-?$' {
            fail("Port '$port'")
        }
    }
    if $original_dest != '' {
        validate_re($sport, '[^\s]+')
    }

    if $ipv4 {
        concat::fragment { "rule-ipv4-${name}":
            order   => $order,
            target  => '/etc/shorewall/rules',
            content => template('shorewall/rule.erb'),
        }
    }

    if $ipv6 {
        concat::fragment { "rule-ipv6-${name}":
            order   => $order,
            target  => '/etc/shorewall6/rules',
            content => template('shorewall/rule.erb'),
        }
    }
}
