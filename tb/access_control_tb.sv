`timescale 1ns/1ps

module access_control_tb;

    reg clk;
    reg rst_n;

    reg req;
    reg write_en;
    reg privilege;

    reg [7:0] address;

    wire grant;
    wire security_alert;

    wire [15:0] violation_count;

    integer tests = 0;
    integer errors = 0;

    access_control dut (
        .clk(clk),
        .rst_n(rst_n),
        .req(req),
        .write_en(write_en),
        .privilege(privilege),
        .address(address),
        .grant(grant),
        .security_alert(security_alert),
        .violation_count(violation_count)
    );

    always #5 clk = ~clk;

    task check(
        input expected_grant,
        input expected_alert,
        input [15:0] expected_count
    );

        begin

            @(posedge clk);
            #1;

            tests = tests + 1;

            if (grant !== expected_grant ||
                security_alert !== expected_alert ||
                violation_count !== expected_count)
            begin

                errors = errors + 1;

                $display(
                    "FAIL: Test %0d",
                    tests
                );

            end

            else
            begin

                $display(
                    "PASS: Test %0d",
                    tests
                );

            end

            @(negedge clk);

        end

    endtask

    initial
    begin

        $dumpfile("security.vcd");
        $dumpvars(0, access_control_tb);

        clk = 0;
        rst_n = 0;

        req = 0;
        write_en = 0;
        privilege = 0;

        address = 0;

        #12;

        @(negedge clk);
        rst_n = 1;

        // Test 1: Normal region read

        req = 1;
        write_en = 0;
        privilege = 0;
        address = 8'h20;

        check(1, 0, 0);

        // Test 2: Normal region write

        req = 1;
        write_en = 1;
        address = 8'h30;

        check(1, 0, 0);

        // Test 3: Unauthorized protected read

        req = 1;
        write_en = 0;
        privilege = 0;
        address = 8'h80;

        check(0, 1, 1);

        // Test 4: Authorized protected read

        req = 1;
        write_en = 0;
        privilege = 1;
        address = 8'h90;

        check(1, 0, 1);

        // Test 5: Protected write attempt

        req = 1;
        write_en = 1;
        privilege = 1;
        address = 8'hA0;

        check(0, 1, 2);

        // Test 6: No request

        req = 0;

        check(0, 0, 2);

        $display("\n============================");

        $display("Total Tests: %0d", tests);

        $display("Failed Tests: %0d", errors);

        if (errors == 0)
        begin
            $display("ALL TESTS PASSED");
        end

        else
        begin
            $fatal(1, "VERIFICATION FAILED");
        end

        $finish;

    end

endmodule